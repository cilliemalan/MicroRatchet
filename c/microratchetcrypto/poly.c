#include "pch.h"
#include <microratchet.h>

typedef struct {
	mr_ctx mr_ctx;
} _mr_poly_ctx;

mr_poly_ctx mr_poly_create(mr_ctx mr_ctx)
{
	_mr_poly_ctx* ctx;
	mr_result r = mr_allocate(mr_ctx, sizeof(_mr_poly_ctx), (void**)&ctx);
	if (r != MR_E_SUCCESS) return 0;

    memset(ctx, 0, sizeof(_mr_poly_ctx));
    ctx->mr_ctx = mr_ctx;

	return ctx;
}

mr_result mr_poly_init(mr_poly_ctx _ctx, const uint8_t* key, uint32_t keysize, const uint8_t* iv, uint32_t ivsize)
{
	_mr_poly_ctx* ctx = _ctx;
	FAILIF(keysize != 32, MR_E_INVALIDSIZE, "keysize != 32");
	FAILIF(ivsize != 16, MR_E_INVALIDSIZE, "ivsize != 16");
	FAILIF(!key || !_ctx || !iv, MR_E_INVALIDARG, "!key || !_ctx || !iv");

	return MR_E_SUCCESS;
}

mr_result mr_poly_process(mr_poly_ctx _ctx, const uint8_t* data, uint32_t amount)
{
	_mr_poly_ctx* ctx = _ctx;
	FAILIF(!amount, MR_E_INVALIDSIZE, "!amount");
	FAILIF(!data || !_ctx, MR_E_INVALIDARG, "!data || !_ctx");

	return MR_E_SUCCESS;
}

mr_result mr_poly_compute(mr_poly_ctx _ctx, uint8_t* output, uint32_t spaceavail)
{
	_mr_poly_ctx* ctx = _ctx;
	FAILIF(!spaceavail, MR_E_INVALIDSIZE, "!spaceavail");
	FAILIF(!output || !_ctx, MR_E_INVALIDARG, "!output || !_ctx");

	return MR_E_SUCCESS;
}

void mr_poly_destroy(mr_poly_ctx ctx)
{
	if (ctx)
	{
		_mr_poly_ctx* _ctx = (_mr_poly_ctx*)ctx;
        mr_ctx mrctx = _ctx->mr_ctx;
		memset(_ctx , 0, sizeof(_mr_poly_ctx));
		mr_free(mrctx, _ctx);
	}
}
