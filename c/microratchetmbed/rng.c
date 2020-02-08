#include "pch.h"
#include <microratchet.h>


typedef struct
{
	mr_ctx mr_ctx;
} _mr_rng_ctx;

mr_rng_ctx mr_rng_create(mr_ctx mr_ctx)
{
	_mr_rng_ctx *ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_rng_ctx), (void **)&ctx);
	if (r != MR_E_SUCCESS)
		return 0;

	*ctx = (_mr_rng_ctx){mr_ctx};
	return ctx;
}

mr_result mr_rng_generate(mr_rng_ctx _ctx, uint8_t *output, uint32_t outputsize)
{
	_mr_rng_ctx *ctx = _ctx;
	FAILIF(outputsize < 1, MR_E_INVALIDSIZE, "outputsize < 1")
	FAILIF(!output, MR_E_INVALIDARG, "!output")

	return MR_E_NOTIMPL;
}

void mr_rng_destroy(mr_rng_ctx _ctx)
{
	if (_ctx)
	{
		_mr_rng_ctx *ctx = _ctx;
		*ctx = (_mr_rng_ctx){0};
		mr_free(ctx->mr_ctx, ctx);
	}
}
