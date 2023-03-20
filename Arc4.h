#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct arc4_context
{
#ifndef NDEBUG
    uint32_t magic;
#endif
    uint8_t i;
    uint8_t j;
    uint8_t s[256];
};

typedef struct arc4_context ARC4_CTX;

D_SEC( E ) void arc4_init(struct arc4_context* ctx, void const* key, size_t key_length);
D_SEC( E ) void arc4_process(struct arc4_context* ctx, void const* src_data, void* dst_data, size_t data_length);
D_SEC( E ) void arc4_discard(struct arc4_context* ctx, size_t length);

#ifdef __cplusplus
}
#endif
