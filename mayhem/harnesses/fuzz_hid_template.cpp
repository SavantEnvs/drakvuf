// Fuzz hidsim's HID template player (drakvuf -a hidsim --hid-template <file>): hid_inject() reads
// the DRAKVUF header (read_header) and replays the evdev `struct input_event` records
// (run_template_injection -> handle_event -> keymap/button/axis mapping -> QMP command JSON).
//
// Environment mocked here (not drakvuf code):
//  * QEMU's QMP monitor: a peer thread on a unix socket in $TMPDIR answers the greeting and every
//    command with {"return": {}}. hid_inject() loops over the template until *has_to_stop; the peer
//    sets it when it sees the cursor-centering command for the second time, which the player sends
//    when it rewinds after reaching the end of the template, so each input is replayed once.
//  * usleep(): template timestamps drive sleeps of up to 10 s; libc's usleep is replaced by a no-op.
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "plugins/hidsim/hid_injection.h"

extern "C" int usleep(useconds_t) { return 0; }

static std::string g_sock;
static std::atomic<bool> g_stop;
static int g_listen = -1;

static void serve_one(int c)
{
    static const char greeting[] = "{\"QMP\": {\"version\": {}, \"capabilities\": []}}\r\n";
    static const char ok[] = "{\"return\": {}}\r\n";
    if (write(c, greeting, sizeof(greeting) - 1) < 0)
        return;
    std::string first_center;
    int n_msgs = 0, n_center = 0;
    char buf[0x4000];
    for (;;)
    {
        ssize_t r = read(c, buf, sizeof(buf));
        if (r <= 0)
            break;
        std::string msg(buf, (size_t)r);
        // msg 1: qmp_capabilities; msg 2: the first centering move (reset_hid_injection).
        n_msgs++;
        if (n_msgs == 2)
        {
            first_center = msg;
            n_center = 1;
        }
        else if (n_msgs > 2 && msg == first_center && ++n_center == 2)
            g_stop.store(true);
        if (write(c, ok, sizeof(ok) - 1) < 0)
            break;
    }
    close(c);
}

static void peer_loop()
{
    for (;;)
    {
        int c = accept(g_listen, nullptr, nullptr);
        if (c < 0)
            continue;
        serve_one(c);
    }
}

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    const char* tmpdir = getenv("TMPDIR");
    std::string dir = std::string(tmpdir && *tmpdir ? tmpdir : "/tmp") + "/hidsim-XXXXXX";
    if (!mkdtemp(&dir[0]))
        abort();
    g_sock = dir + "/qmp.sock";
    g_listen = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa = {};
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", g_sock.c_str());
    if (g_listen < 0 || bind(g_listen, (struct sockaddr*)&sa, sizeof(sa)) != 0 || listen(g_listen, 4) != 0)
        abort();
    std::thread(peer_loop).detach();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::string path = g_sock.substr(0, g_sock.rfind('/')) + "/template-XXXXXX";
    int fd = mkstemp(&path[0]);
    if (fd < 0)
        return 0;
    size_t off = 0;
    while (off < size)
    {
        ssize_t w = write(fd, data + off, size - off);
        if (w <= 0)
            break;
        off += (size_t)w;
    }
    close(fd);

    g_stop.store(false);
    std::atomic<uint32_t> coords{0};
    hid_inject(g_sock.c_str(), path.c_str(), false, &coords, &g_stop);
    unlink(path.c_str());
    return 0;
}
