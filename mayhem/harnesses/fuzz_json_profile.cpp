// Fuzz drakvuf's JSON profile symbol loader: profiles (--json-kernel, --json-ntdll, ... and the
// plugin-specific ones) are parsed with json-c and json_get_symbols() builds the symbol table from
// an IST ("symbols") or Rekall ("$FUNCTIONS"/"$CONSTANTS") layout.
#include <cstdint>
#include <string>
#include <json-c/json.h>


#include "libdrakvuf/libdrakvuf.h"


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    json_tokener* tok = json_tokener_new();
    if (!tok)
        return 0;
    json_object* json = json_tokener_parse_ex(tok, reinterpret_cast<const char*>(data), (int)size);
    json_tokener_free(tok);
    if (!json)
        return 0;

    symbols_t* symbols = json_get_symbols(json);
    if (symbols)
    {
        volatile addr_t sum = 0;
        for (size_t i = 0; i < symbols->count; i++)
            if (symbols->symbols[i].name)
                sum += symbols->symbols[i].rva + symbols->symbols[i].name[0];
        drakvuf_free_symbols(symbols);
    }
    json_object_put(json);
    return 0;
}
