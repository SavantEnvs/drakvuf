#!/usr/bin/env bash
# mayhem/build.sh — drakvuf fuzz harnesses + upstream unit tests.
# drakvuf's real input (guest memory) needs a live Xen VM; its host-side parsers do not. This builds
# drakvuf's own libraries (libdrakvuf, xen_helper, libusermode, libhook, plugin helpers) from source
# with the fuzz flags into one static archive and links each harness against it. Upstream's meson
# build is not used: it requires a configured libvmi/Xen install, werror+LTO and `git describe`.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
LIBVMI=/opt/toolchains/deps/libvmi-ed40729
B="$SRC/mayhem/build"
mkdir -p "$B"
printf '#define PACKAGE_NAME "DRAKVUF"\n#define PACKAGE_VERSION "1.1"\n' > "$B/config.h"

INC="-DHAVE_CONFIG_H -I$B -I$SRC/src -I$SRC -I$LIBVMI/include $(pkg-config --cflags glib-2.0 json-c)"
WARN="-w"
LIBS_TAIL="-lxenctrl -lxenforeignmemory -lxentoollog -lxenlight -lxenstore -lz -ldl -lm -lpthread"
LIBS="$LIBVMI/lib/libvmi.a $(pkg-config --libs glib-2.0 json-c) $LIBS_TAIL"

C_SRCS=(src/libdrakvuf/*.c src/xen_helper/xen_helper.c $(find src/libinjector -name '*.c' | sort))
CINC="-I$SRC/src/libinjector -I$SRC/src/libinjector/linux -I$SRC/src/libinjector/linux/methods -I$SRC/src/libinjector/win -I$SRC/src/libinjector/win/methods"
CXX_SRCS=(src/libusermode/userhook.cpp src/libusermode/userhook_pf.cpp src/libusermode/userhook_inject.cpp
          src/libusermode/running.cpp src/libusermode/utils.cpp src/libusermode/printers/printers.cpp
          src/libusermode/printers/utils.cpp src/libhook/hooks/*.cpp src/plugins/plugins_ex.cpp
          src/plugins/procmon/linux_utils.cpp src/plugins/procmon/winnt.cpp
          src/plugins/hidsim/hid_injection.cpp src/plugins/hidsim/qmp/qmp_connection.cpp src/plugins/output_format/ostream.cpp)

# build_lib <outdir> <cflags>: compile the project sources into <outdir>/libdrakvuf_all.a
build_lib() {
    local out="$1" flags="$2" f o objs=()
    mkdir -p "$out"
    for f in "${C_SRCS[@]}"; do
        o="$out/$(echo "$f" | tr / _).o"; objs+=("$o")
        echo "$CC $flags $INC $CINC $WARN -c $f -o $o"
    done > "$out/cmds"
    for f in "${CXX_SRCS[@]}"; do
        o="$out/$(echo "$f" | tr / _).o"; objs+=("$o")
        echo "$CXX -std=c++2a $flags $INC $WARN -c $f -o $o"
    done >> "$out/cmds"
    # shellcheck disable=SC2016
    xargs -P "$MAYHEM_JOBS" -I{} sh -c '{}' < "$out/cmds"
    rm -f "$out/libdrakvuf_all.a"
    ar rcs "$out/libdrakvuf_all.a" "${objs[@]}"
}

# 1) Project, instrumented for fuzzing (ASan+UBSan, SanCov, DWARF 3).
FUZZ_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link"
build_lib "$B/fuzz" "$FUZZ_FLAGS"

# json-c, instrumented, for json_profile only: a profile file is parsed by json-c's tokenizer before
# json_get_symbols() walks it, so the parser is part of that target. Out of tree under mayhem/build.
JSONC_SRC=/opt/toolchains/deps/json-c-0.18/src
JSONC="$B/json-c-inst"
cmake -G Ninja -S "$JSONC_SRC" -B "$B/json-c" -DCMAKE_BUILD_TYPE=None -DCMAKE_C_FLAGS="$FUZZ_FLAGS" \
    -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON -DBUILD_TESTING=OFF -DBUILD_APPS=OFF \
    -DDISABLE_WERROR=ON -DCMAKE_INSTALL_PREFIX="$JSONC" >/dev/null
ninja -C "$B/json-c" -j "$MAYHEM_JOBS" install >/dev/null

# 2) Harnesses: libFuzzer binary + standalone reproducer each.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"
for h in fuzz_dll_hooks fuzz_output_format fuzz_json_profile fuzz_hid_template; do
    hinc="" ; hlibs="$LIBS"
    if [ "$h" = fuzz_json_profile ]; then
        hinc="-I$JSONC/include -I$JSONC/include/json-c"
        hlibs="$LIBVMI/lib/libvmi.a $JSONC/lib/libjson-c.a $(pkg-config --libs glib-2.0) $LIBS_TAIL"
    fi
    $CXX -std=c++2a $FUZZ_FLAGS $hinc $INC $WARN -c "$SRC/mayhem/harnesses/$h.cpp" -o "$B/$h.o"
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/$h.o" "$B/lsan_off.o" \
        "$B/fuzz/libdrakvuf_all.a" $hlibs -o "/mayhem/$h"
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/standalone_main.o" "$B/$h.o" "$B/lsan_off.o" \
        "$B/fuzz/libdrakvuf_all.a" $hlibs -o "/mayhem/$h-standalone"
done

# 3) Upstream's `check` unit tests, NORMAL flags (independent of the fuzz build).
TEST_FLAGS="-O1 -g $COVERAGE_FLAGS"
build_lib "$B/test" "$TEST_FLAGS"
mkdir -p "$B/tests"
CHECK_LIBS="$(pkg-config --libs check)"
declare -A TESTS=(
    [output_format_check]=src/plugins/output_format/check.cpp
    [procmon_check]=src/plugins/procmon/check.cpp
    [libusermode_printers_check]=src/libusermode/printers/check.cpp
    [userhook_check]=src/libusermode/check.cpp
    [plugin_utils_check]=src/plugins/plugin_utils_check.cpp
)
$CXX -std=c++2a $TEST_FLAGS $INC $WARN -c src/plugins/plugin_utils.cpp -o "$B/test/plugin_utils.o"
for t in "${!TESTS[@]}"; do
    extra=""
    [ "$t" = plugin_utils_check ] && extra="$B/test/plugin_utils.o"
    # check.h defines a `fail(...)` macro that clashes with std::ios::fail() when it is included
    # before <ios> (plugin_utils_check.cpp does); pre-include <ios> so the suite compiles unchanged.
    $CXX -std=c++2a $TEST_FLAGS $INC $WARN -include ios "${TESTS[$t]}" $extra "$B/test/libdrakvuf_all.a" \
        $LIBS $CHECK_LIBS $COVERAGE_FLAGS -o "$B/tests/$t"
done
echo "build.sh: done"
