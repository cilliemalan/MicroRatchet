#include "pch.h"
#include <microratchet.h>

#ifndef HAVE_AESGCM
#define HAVE_AESGCM
#endif
#include <wolfssl/wolfcrypt/aes.h>

typedef struct {
	mr_ctx mr_ctx;
	Aes wc_aes;
	const unsigned char* iv;
	unsigned int ivsize;
	unsigned char authtag[16];
} _mr_gmac_ctx;


mr_gmac_ctx mr_gmac_create(mr_ctx mr_ctx)
{
	_mr_gmac_ctx *ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_gmac_ctx), &ctx);
	if (r != E_SUCCESS) return 0;

	ctx->mr_ctx = mr_ctx;
	memset(&ctx->wc_aes, 0, sizeof(ctx->wc_aes));
	return ctx;
}

int mr_gmac_init(mr_gmac_ctx _ctx, const unsigned char* key, unsigned int keysize, const unsigned char* iv, unsigned int ivsize)
{
	_mr_gmac_ctx* ctx = _ctx;
	if (keysize != 16 && keysize != 32) return E_INVALIDSIZE;
	if (!ivsize) return E_INVALIDSIZE;
	if (!key || !iv || !_ctx) return E_INVALIDARGUMENT;

	int r = wc_AesGcmSetKey(&ctx->wc_aes, key, keysize);
	if (r != 0) return E_INVALIDOP;
	ctx->iv = iv;
	ctx->ivsize = ivsize;
	memset(ctx->authtag, 0, sizeof(ctx->authtag));
	mr_gmac_init_cb(E_SUCCESS, ctx, ctx->mr_ctx);
	return E_SUCCESS;
}

int mr_gmac_process(mr_gmac_ctx _ctx, const unsigned char* data, unsigned int amount)
{
	_mr_gmac_ctx* ctx = _ctx;
	if (!data || !amount || !_ctx) return E_INVALIDARGUMENT;

	int r = wc_AesGcmEncrypt(&ctx->wc_aes, 0, 0, 0,
		ctx->iv, ctx->ivsize,
		ctx->authtag, sizeof(ctx->authtag),
		data, amount);
	if (r != 0) return E_INVALIDOP;
	mr_gmac_process_cb(E_SUCCESS, ctx, ctx->mr_ctx);
	return E_SUCCESS;
}

int mr_gmac_compute(mr_gmac_ctx _ctx, unsigned char* output, unsigned int spaceavail)
{
	_mr_gmac_ctx* ctx = _ctx;
	if (!output || !ctx)return E_INVALIDARGUMENT;
	if (spaceavail < 4) return E_INVALIDSIZE;

	memcpy(output, ctx->authtag, spaceavail);
	memset(ctx->authtag, 0, sizeof(ctx->authtag));
	mr_gmac_compute_cb(E_SUCCESS, ctx, ctx->mr_ctx);
	return E_SUCCESS;
}

void mr_gmac_destroy(mr_gmac_ctx ctx)
{
	if (ctx)
	{
		_mr_gmac_ctx* _ctx = (_mr_gmac_ctx*)ctx;
		wc_AesFree(&_ctx->wc_aes);
		mr_free(_ctx->mr_ctx, _ctx);
	}
}
