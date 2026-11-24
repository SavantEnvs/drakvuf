// Fuzz drakvuf's guest-string escaping and output formatters. Every plugin prints strings read from
// guest memory (process names, paths, environment variables, registry values) through these:
// kvfmt/jsonfmt/csvfmt/deffmt print_data() for Qstr/Rstr/BinaryString (jsonfmt/csvfmt/deffmt call
// drakvuf_escape_str), libusermode escape_str() for usermode-hook arguments, and procmon's
// parse_environment_variable() for Linux process environments.
#include <cstdint>
#include <sstream>
#include <string>

#include "plugins/output_format/common.h"
#include "plugins/output_format/kvfmt.h"
#include "plugins/output_format/jsonfmt.h"
#include "plugins/output_format/csvfmt.h"
#include "plugins/output_format/deffmt.h"
#include "plugins/procmon/linux_utils.h"
#include "libusermode/printers/utils.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Guest strings reach the formatters as NUL-terminated C strings.
    std::string s(reinterpret_cast<const char*>(data), size);
    std::string cstr = s.substr(0, s.find('\0'));

    std::stringstream ss;
    kvfmt::print_data(ss, fmt::Qstr(cstr), ',');
    kvfmt::print_data(ss, fmt::Rstr(cstr), ',');
    kvfmt::print_data(ss, fmt::BinaryString(data, size), ',');
    jsonfmt::print_data(ss, fmt::Qstr(cstr), ',');
    jsonfmt::print_data(ss, fmt::Rstr(cstr), ',');
    jsonfmt::print_data(ss, fmt::BinaryString(data, size), ',');
    csvfmt::print_data(ss, fmt::Qstr(cstr), ',');
    csvfmt::print_data(ss, fmt::Rstr(cstr), ',');
    csvfmt::print_data(ss, fmt::BinaryString(data, size), ',');
    deffmt::print_data(ss, fmt::Qstr(cstr), ',');
    deffmt::print_data(ss, fmt::Rstr(cstr), ',');
    deffmt::print_data(ss, fmt::BinaryString(data, size), ',');

    std::string esc = escape_str(s);
    auto kv = parse_environment_variable(cstr.c_str());
    ss << esc << kv.first << kv.second;
    return ss.str().empty() ? 0 : 0;
}
