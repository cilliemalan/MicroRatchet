#include "pch.h"
#include <microratchet.h>

#include <wolfssl/wolfcrypt/poly1305.h>
#include <wolfssl/wolfcrypt/aes.h>

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

mr_result_t mr_poly_init(mr_poly_ctx _ctx, const uint8_t* key, uint32_t keysize, const uint8_t* iv, uint32_t ivsize)
{
	_mr_poly_ctx* ctx = _ctx;
	if (keysize != 32) return E_INVALIDSIZE;
	if (ivsize != 16) return E_INVALIDSIZE;
	if (!key || !_ctx || !iv) return E_INVALIDARGUMENT;

	uint8_t tkey[32];
	memcpy(tkey, key, 16);
	Aes aes;
	int r = wc_AesSetKeyDirect(&aes, key + 16, 16, 0, AES_ENCRYPTION);
	if (r != 0) return E_INVALIDOP;
	wc_AesEncryptDirect(&aes, tkey + 16, iv);

	r = wc_Poly1305SetKey(&ctx->wc_poly, tkey, 32);
	if (r != 0) return E_INVALIDOP;
	return E_SUCCESS;
}

mr_result_t mr_poly_process(mr_poly_ctx _ctx, const uint8_t* data, uint32_t amount)
{
	_mr_poly_ctx* ctx = _ctx;
	if (!amount) return E_INVALIDSIZE;
	if (!data || !_ctx) return E_INVALIDARGUMENT;

	int r =  wc_Poly1305Update(&ctx->wc_poly, data, amount);
	if (r != 0) return E_INVALIDOP;
	return E_SUCCESS;
}

mr_result_t mr_poly_compute(mr_poly_ctx _ctx, uint8_t* output, uint32_t spaceavail)
{
	_mr_poly_ctx* ctx = _ctx;
	if (!spaceavail) return E_INVALIDSIZE;
	if (!output || !_ctx) return E_INVALIDARGUMENT;

	if (spaceavail < 16)
	{
		uint8_t tmp[16];
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
	return E_SUCCESS;
}

void mr_poly_destroy(mr_poly_ctx ctx)
{
	if (ctx)
	{
		_mr_poly_ctx* _ctx = (_mr_poly_ctx*)ctx;
		*_ctx = (_mr_poly_ctx){ 0 };
		mr_free(_ctx->mr_ctx, _ctx);
	}
}
