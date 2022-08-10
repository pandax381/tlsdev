#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdint.h>

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif
#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#include <endian.h>
#if __BIG_ENDIAN__
#define htonll(x) (x)
#define ntohll(x) (x)
#else
#define htonll(x) (((uint64_t)htonl((x) & 0xffffffff) << 32) | htonl((x) >> 32))
#define ntohll(x) (((uint64_t)ntohl((x) & 0xffffffff) << 32) | ntohl((x) >> 32))
#endif

extern void
hexdump(FILE *fp, const void *data, size_t size);
extern void
cdump(FILE *fp, const void *data, size_t size, char *name);

#endif