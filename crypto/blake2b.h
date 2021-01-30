#ifndef __BLAKE2B_H__
#define __BLAKE2B_H__

#include <stddef.h>
#include <stdint.h>

#include "sph_types.h"

#define SPH_SIZE_blake2b 64

#if defined(_MSC_VER) || defined(__x86_64__) || defined(__x86__)
#define NATIVE_LITTLE_ENDIAN
#endif

typedef struct {
#ifndef DOXYGEN_IGNORE
	unsigned char buf[128];    /* first field, for alignment */
	sph_u32 h[8];
	sph_u32 t[2];
    size_t c;
	size_t outlen;
#endif
} blake2b_context;

#if defined(__cplusplus)
extern "C" {
#endif

void blake2b_init(void *cc);
void blake2b(void *cc, const void *in, size_t inlen);
void blake2b_close(void *cc, void *out);

#if defined(__cplusplus)
}
#endif

#endif
