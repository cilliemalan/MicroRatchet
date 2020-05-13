#pragma once

#ifdef MR_X64
MR_ALIGN(16)
#define NUM_ROUNDKEYS 68
#else
#define NUM_ROUNDKEYS 64
#endif
typedef struct {
	uint32_t roundkeys[NUM_ROUNDKEYS];
	uint32_t numrounds;
	mr_ctx mr_ctx;
} _mr_aes_ctx;

