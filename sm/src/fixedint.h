/*
    Portable header to provide the 32 and 64 bits type.

    Not a compatible replacement for <stdint.h>, do not blindly use it as such.
*/

#ifndef __FIXEDINT_H__
#define __FIXEDINT_H__

#include <sbi/sbi_types.h>
typedef signed char int8_t;
typedef unsigned uint_fast16_t;
typedef unsigned uint_fast8_t;

#define UINT8_MAX 0xFF
#define UINT16_MAX 0xFFFF
#define UINT32_MAX 0xFFFFFFFF
#define UINT64_MAX 0xFFFFFFFFFFFFFFFF
#define SIZE_MAX (sizeof(size_t) == 8 ? UINT64_MAX : UINT32_MAX)

#endif
