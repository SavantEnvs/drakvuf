// Fuzz the DLL hooks list parser (drakvuf --dll-hooks-list <file>, used by apimon/memdump):
// drakvuf_load_dll_hook_config() reads the file line by line, parse_entry() builds hook entries and
// argument printers, wanted_hooks_t::add_hook() stores them, and visit_hooks_for() matches DLL names.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <unistd.h>

#include "libusermode/userhook.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    const char* tmpdir = getenv("TMPDIR");
    std::string path = std::string(tmpdir && *tmpdir ? tmpdir : "/tmp") + "/dllhooks-XXXXXX";
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

    wanted_hooks_t wanted;
    bool ok = true;
    try
    {
        // drakvuf is not used when a hooks list path is given; the filter keeps every entry.
        drakvuf_load_dll_hook_config(nullptr, path.c_str(), false,
            [](const plugin_target_config_entry_t&) { return false; }, wanted);
    }
    catch (const std::runtime_error&)
    {
        ok = false; // documented rejection of a malformed line
    }
    unlink(path.c_str());

    if (ok)
    {
        size_t n = 0;
        auto visit = [&n](const plugin_target_config_entry_t& e) { n += e.argument_printers.size() + e.function_name.size(); };
        for (const char* dll : {"ntdll.dll", "\\Windows\\System32\\kernel32.dll", "ws2_32.dll", "a"})
            wanted.visit_hooks_for(dll, visit);
        // Also match against the first line of the input, as a guest-controlled module name would be.
        std::string first(reinterpret_cast<const char*>(data), size);
        first = first.substr(0, first.find_first_of(",\n"));
        wanted.visit_hooks_for(first, visit);
        if (n == (size_t)-1)
            abort();
    }
    return 0;
}
