#include "pch.h"
#include <microratchet.h>
#include <openssl/sha.h>

typedef struct {
	mr_ctx mr_ctx;
	SHA256_CTX sha;
} _mr_sha_ctx;

mr_sha_ctx mr_sha_create(mr_ctx mr_ctx)
{
	_mr_sha_ctx *ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_sha_ctx), (void**)&ctx);
	if (r != MR_E_SUCCESS) return 0;

	mr_memzero(ctx, sizeof(_mr_sha_ctx));
    ctx->mr_ctx = mr_ctx;

	return ctx;
}

mr_result mr_sha_init(mr_sha_ctx _ctx)
{
	FAILIF(!_ctx, MR_E_INVALIDARG, "ctx must be specified");
	_mr_sha_ctx* ctx = (_mr_sha_ctx*)_ctx;

	int r = SHA256_Init(&ctx->sha);
	FAILIF(r != 1, MR_E_INVALIDOP, "Failed to initialize SHA25");

	return MR_E_SUCCESS;
}

mr_result mr_sha_process(mr_sha_ctx _ctx, const uint8_t* data, uint32_t howmuch)
{
	FAILIF(!_ctx || !data, MR_E_INVALIDARG, "!ctx || !data");
	FAILIF(!howmuch, MR_E_SUCCESS, "!howmuch");
	_mr_sha_ctx* ctx = (_mr_sha_ctx*)_ctx;

	int r = SHA256_Update(&ctx->sha, data, howmuch);
	FAILIF(r != 1, MR_E_INVALIDOP, "Failed to process SHA256");

	return MR_E_SUCCESS;
}

mr_result mr_sha_compute(mr_sha_ctx _ctx, uint8_t* output, uint32_t spaceavail)
{
	FAILIF(!_ctx || !output, MR_E_INVALIDARG, "!ctx || !output");
	FAILIF(spaceavail < 32, MR_E_INVALIDSIZE, "spaceavail < 32");
	_mr_sha_ctx* ctx = (_mr_sha_ctx*)_ctx;

	int r = SHA256_Final(output, &ctx->sha);
	FAILIF(r != 1, MR_E_INVALIDOP, "Failed to process SHA256");

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
