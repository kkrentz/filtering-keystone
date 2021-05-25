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

#endif
