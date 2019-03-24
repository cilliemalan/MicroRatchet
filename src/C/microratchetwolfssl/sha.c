#include "pch.h"
#include <microratchet.h>
#include <wolfssl/wolfcrypt/sha256.h>

typedef struct {
	mr_ctx mr_ctx;
	wc_Sha256 wc_sha;
} _mr_sha_ctx;

mr_sha_ctx mr_sha_create(mr_ctx mr_ctx)
{
	_mr_sha_ctx *ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_sha_ctx), &ctx);
	if (r != E_SUCCESS) return 0;

	ctx->mr_ctx = mr_ctx;
	memset(&ctx->wc_sha, 0, sizeof(ctx->wc_sha));
	return ctx;
}

int mr_sha_init(mr_sha_ctx ctx)
{
	if (!ctx) return E_INVALIDARG;
	_mr_sha_ctx* _ctx = (_mr_sha_ctx*)ctx;

	int r = wc_InitSha256(&_ctx->wc_sha);
	if (r != 0) return E_INVALIDOP;
	return E_SUCCESS;
}

int mr_sha_process(mr_sha_ctx ctx, const unsigned char* data, unsigned int howmuch)
{
	if (!ctx || !data) return E_INVALIDARG;
	if (!howmuch) return E_SUCCESS;
	_mr_sha_ctx* _ctx = (_mr_sha_ctx*)ctx;

	int r = wc_Sha256Update(&_ctx->wc_sha, data, howmuch);
	if (r != 0) return E_INVALIDOP;
	return E_SUCCESS;
}

int mr_sha_compute(mr_sha_ctx ctx, unsigned char* output, unsigned int spaceavail)
{
	if (!ctx || !output) return E_INVALIDARG;
	if (spaceavail < 32) return E_INVALIDSIZE;
	_mr_sha_ctx* _ctx = (_mr_sha_ctx*)ctx;

	int r = wc_Sha256Final(&_ctx->wc_sha, output);
	if (r != 0) return E_INVALIDOP;
	return E_SUCCESS;
}

void mr_sha_destroy(mr_sha_ctx ctx)
{
	if (ctx)
	{
		_mr_sha_ctx* _ctx = (_mr_sha_ctx*)ctx;
		wc_Sha256Free(&_ctx->wc_sha);
		mr_free(_ctx->mr_ctx, _ctx);
	}
}
