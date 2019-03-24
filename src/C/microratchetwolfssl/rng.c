#include "pch.h"
#include <microratchet.h>
#include <wolfssl/wolfcrypt/random.h>

typedef struct {
	mr_ctx mr_ctx;
	WC_RNG rng;
} _mr_rng_ctx;

mr_rng_ctx mr_rng_create(mr_ctx mr_ctx)
{
	_mr_rng_ctx* ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_rng_ctx), &ctx);
	if (r != E_SUCCESS) return 0;

	ctx->mr_ctx = mr_ctx;
	memset(&ctx->rng, 0, sizeof(ctx->rng));
	return ctx;
}

int mr_rng_generate(mr_rng_ctx _ctx, unsigned char* output, unsigned int outputsize)
{
	_mr_rng_ctx* ctx = _ctx;
	if (outputsize < 1) return E_INVALIDSIZE;
	if (!output) return E_INVALIDARGUMENT;

	if (ctx->rng.seed.handle == 0)
	{
		int r = wc_InitRng(&ctx->rng);
		if (r != 0) return E_INVALIDOP;
	}

	int r = wc_RNG_GenerateBlock(&ctx->rng, output, outputsize);
	if (r != 0) return E_INVALIDOP;
	return E_SUCCESS;
}

void mr_rng_destroy(mr_rng_ctx _ctx)
{
	if (_ctx)
	{
		_mr_rng_ctx* ctx = _ctx;
		wc_FreeRng(&ctx->rng);
		mr_free(ctx->mr_ctx, ctx);
	}
}
