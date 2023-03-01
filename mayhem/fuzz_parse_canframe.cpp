#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "can.h"

extern "C" int parse_canframe(char *cs, struct canfd_frame *cf);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    char* cs = strdup(provider.ConsumeRandomLengthString(1000).c_str());
    canfd_frame cf;

    parse_canframe(cs, &cf);

    free(cs);

    return 0;
}
