/* Embedded C with HolyC-looking type names: not HolyC. */
#include <stdint.h>

typedef uint8_t U8;
typedef int32_t I32;
typedef int64_t I64;
typedef double F64;

static U8 buffer[64];

I64 checksum(const U8 *data, I32 len)
{
    I64 sum = 0;
    for (I32 i = 0; i < len; i++) {
        sum += data[i];
    }
    return sum;
}

F64 average(const U8 *data, I32 len)
{
    if (len == 0) {
        return 0.0;
    }
    return (F64)checksum(data, len) / len;
}
