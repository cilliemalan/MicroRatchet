#include "pch.h"
#include <microratchet.h>
#include <openssl/rand.h>

typedef struct
{
	mr_ctx mr_ctx;
} _mr_rng_ctx;

mr_rng_ctx mr_rng_create(mr_ctx mr_ctx)
{
	_mr_rng_ctx* ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_rng_ctx), (void**)&ctx);
	if (r != MR_E_SUCCESS)
		return 0;

	mr_memzero(ctx, sizeof(_mr_rng_ctx));
    ctx->mr_ctx = mr_ctx;

	return ctx;
}

mr_result mr_rng_generate(mr_rng_ctx _ctx, uint8_t* output, uint32_t outputsize)
{
	_mr_rng_ctx* ctx = _ctx;
	FAILIF(outputsize < 1, MR_E_INVALIDSIZE, "outputsize < 1");
	FAILIF(!output, MR_E_INVALIDARG, "!output");

	int r = RAND_bytes(output, outputsize);
	FAILIF(r != 1, MR_E_INVALIDOP, "Could not generate random numbers");

	return MR_E_SUCCESS;
}

void mr_rng_destroy(mr_rng_ctx _ctx)
{
	if (_ctx)
	{
		_mr_rng_ctx* ctx = _ctx;
		mr_ctx mrctx = ctx->mr_ctx;
		mr_memzero(ctx, sizeof(_mr_rng_ctx));
		mr_free(mrctx, ctx);
	}
}
