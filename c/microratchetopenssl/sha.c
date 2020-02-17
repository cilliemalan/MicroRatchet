#include "pch.h"
#include <microratchet.h>

typedef struct {
	mr_ctx mr_ctx;
} _mr_sha_ctx;

mr_sha_ctx mr_sha_create(mr_ctx mr_ctx)
{
	_mr_sha_ctx *ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_sha_ctx), (void**)&ctx);
	if (r != MR_E_SUCCESS) return 0;

	*ctx = (_mr_sha_ctx){
		.mr_ctx = mr_ctx
	};
	return ctx;
}

mr_result mr_sha_init(mr_sha_ctx ctx)
{
	FAILIF(!ctx, MR_E_INVALIDARG, "!ctx")
	_mr_sha_ctx* _ctx = (_mr_sha_ctx*)ctx;

	return MR_E_NOTIMPL;
}

mr_result mr_sha_process(mr_sha_ctx ctx, const uint8_t* data, uint32_t howmuch)
{
	FAILIF(!ctx || !data, MR_E_INVALIDARG, "!ctx || !data")
	FAILIF(!howmuch, MR_E_SUCCESS, "!howmuch")
	_mr_sha_ctx* _ctx = (_mr_sha_ctx*)ctx;

	return MR_E_NOTIMPL;
}

mr_result mr_sha_compute(mr_sha_ctx ctx, uint8_t* output, uint32_t spaceavail)
{
	FAILIF(!ctx || !output, MR_E_INVALIDARG, "!ctx || !output")
	FAILIF(spaceavail < 32, MR_E_INVALIDSIZE, "spaceavail < 32")
	_mr_sha_ctx* _ctx = (_mr_sha_ctx*)ctx;

	return MR_E_NOTIMPL;
}

void mr_sha_destroy(mr_sha_ctx ctx)
{
	if (ctx)
	{
		_mr_sha_ctx* _ctx = (_mr_sha_ctx*)ctx;
		*_ctx = (_mr_sha_ctx){ 0 };
		mr_free(_ctx->mr_ctx, _ctx);
	}
}
