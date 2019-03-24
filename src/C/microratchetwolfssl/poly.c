#include "pch.h"
#include <microratchet.h>

#include <wolfssl/wolfcrypt/poly1305.h>

//Poly1305

typedef struct {
	mr_ctx mr_ctx;
	Poly1305 wc_poly;
} _mr_poly_ctx;

mr_poly_ctx mr_poly_create(mr_ctx mr_ctx)
{
	_mr_poly_ctx *ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_poly_ctx), &ctx);
	if (r != E_SUCCESS) return 0;

	ctx->mr_ctx = mr_ctx;
	memset(&ctx->wc_poly, 0, sizeof(ctx->wc_poly));
	return ctx;
}

int mr_poly_init(mr_poly_ctx _ctx, const unsigned char* key, unsigned int keysize)
{
	_mr_poly_ctx* ctx = _ctx;
	if (keysize != 32) return E_INVALIDSIZE;
	if (!key || !_ctx) return E_INVALIDARGUMENT;

	int r = wc_Poly1305SetKey(&ctx->wc_poly, key, keysize);
	if (r != 0) return E_INVALIDOP;
	mr_poly_init_cb(E_SUCCESS, ctx, ctx->mr_ctx);
	return E_SUCCESS;
}

int mr_poly_process(mr_poly_ctx _ctx, const unsigned char* data, unsigned int amount)
{
	_mr_poly_ctx* ctx = _ctx;
	if (!amount) return E_INVALIDSIZE;
	if (!data || !_ctx) return E_INVALIDARGUMENT;

	int r =  wc_Poly1305Update(&ctx->wc_poly, data, amount);
	if (r != 0) return E_INVALIDOP;
	mr_poly_process_cb(E_SUCCESS, ctx, ctx->mr_ctx);
	return E_SUCCESS;
}

int mr_poly_compute(mr_poly_ctx _ctx, unsigned char* output, unsigned int spaceavail)
{
	_mr_poly_ctx* ctx = _ctx;
	if (!spaceavail) return E_INVALIDSIZE;
	if (!output || !_ctx) return E_INVALIDARGUMENT;

	if (spaceavail < 16)
	{
		unsigned char tmp[16];
		int r = wc_Poly1305Final(&ctx->wc_poly, tmp);
		if (r != 0) return E_INVALIDOP;
		memcpy(output, tmp, spaceavail);
	}
	else if (spaceavail == 16)
	{
		int r = wc_Poly1305Final(&ctx->wc_poly, output);
		if (r != 0) return E_INVALIDOP;
	}
	else
	{
		int r = wc_Poly1305Final(&ctx->wc_poly, output);
		if (r != 0) return E_INVALIDOP;
		memset(output + 16, 0, spaceavail - 16);
	}
	mr_poly_compute_cb(E_SUCCESS, ctx, ctx->mr_ctx);
	return E_SUCCESS;
}

void mr_poly_destroy(mr_poly_ctx ctx)
{
	if (ctx)
	{
		_mr_poly_ctx* _ctx = (_mr_poly_ctx*)ctx;
		mr_free(_ctx->mr_ctx, _ctx);
	}
}
