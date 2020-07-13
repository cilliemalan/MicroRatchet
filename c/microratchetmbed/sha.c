#include "pch.h"
#include <microratchet.h>
#include <mbedtls/sha256.h>

typedef struct {
	mr_ctx mr_ctx;
	mbedtls_sha256_context sha_ctx;
} _mr_sha_ctx;

mr_sha_ctx mr_sha_create(mr_ctx mr_ctx)
{
	_mr_sha_ctx *ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_sha_ctx), (void**)&ctx);
	if (r != MR_E_SUCCESS) return 0;
	ctx->mr_ctx = mr_ctx;
	mbedtls_sha256_init(&ctx->sha_ctx);
	return ctx;
}

mr_result mr_sha_init(mr_sha_ctx _ctx)
{
	FAILIF(!_ctx, MR_E_INVALIDARG, "!ctx");
	_mr_sha_ctx* ctx = (_mr_sha_ctx*)_ctx;

	int r = mbedtls_sha256_starts_ret(&ctx->sha_ctx, 0);
	FAILIF(r, MR_E_INVALIDOP, "Failed to initialize SHA256");
	return MR_E_SUCCESS;
}

mr_result mr_sha_process(mr_sha_ctx _ctx, const uint8_t* data, uint32_t howmuch)
{
	FAILIF(!_ctx || !data, MR_E_INVALIDARG, "!ctx || !data");
	FAILIF(!howmuch, MR_E_INVALIDARG, "!howmuch");
	_mr_sha_ctx* ctx = (_mr_sha_ctx*)_ctx;

	mbedtls_sha256_update_ret(&ctx->sha_ctx, data, howmuch);

	return MR_E_SUCCESS;
}

mr_result mr_sha_compute(mr_sha_ctx _ctx, uint8_t* output, uint32_t spaceavail)
{
	FAILIF(!_ctx || !output, MR_E_INVALIDARG, "!ctx || !output");
	FAILIF(spaceavail < 32, MR_E_INVALIDSIZE, "spaceavail < 32");
	_mr_sha_ctx* ctx = (_mr_sha_ctx*)_ctx;

	int r = mbedtls_sha256_finish_ret(&ctx->sha_ctx, output);
	FAILIF(r, MR_E_INVALIDOP, "failed to finish SHA256 operation");

	return MR_E_SUCCESS;
}

void mr_sha_destroy(mr_sha_ctx ctx)
{
	if (ctx)
	{
		_mr_sha_ctx* _ctx = (_mr_sha_ctx*)ctx;
		mr_ctx mrctx = _ctx->mr_ctx;
		mr_memzero(_ctx, sizeof(_mr_sha_ctx));
		mr_free(mrctx, _ctx);
	}
}
