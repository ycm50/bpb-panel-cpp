#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

/* Minimal lwIP port layer for Windows / UCRT64 (and generic POSIX). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#define LWIP_NO_STDINT_H 0
#define LWIP_NO_INTTYPES_H 0

#define LWIP_PLATFORM_DIAG(x) do { printf x; } while (0)
#define LWIP_PLATFORM_ASSERT(x) do { printf("lwip assert: %s\n", x); abort(); } while (0)

/* Byte order: x86 / ARM64 are little endian. */
#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

/* lwIP declares lwip_htonl itself; stop the platform headers from also
   providing byte-order macros, which collide on MinGW. */
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1

#define LWIP_RAND() ((u32_t)rand())

#define LWIP_PACKED_STRUCT_BEGIN __pragma(pack(push, 1))
#define LWIP_PACKED_STRUCT_END __pragma(pack(pop))

#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_STRUCT __attribute__((packed))
#define PACK_STRUCT_END
#define PACK_STRUCT_FIELD(x) x

#endif /* LWIP_ARCH_CC_H */
