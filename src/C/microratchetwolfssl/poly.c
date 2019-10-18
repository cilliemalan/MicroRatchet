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
	int r = mr_allocate(mr_ctx, sizeof(_mr_poly_ctx), (void**)&ctx);
	if (r != MR_E_SUCCESS) return 0;

	*ctx = (_mr_poly_ctx){
		.mr_ctx = mr_ctx,
		.wc_poly = (Poly1305){ 0 }
	};
	return ctx;
}

mr_result mr_poly_init(mr_poly_ctx _ctx, const uint8_t* key, uint32_t keysize, const uint8_t* iv, uint32_t ivsize)
{
	_mr_poly_ctx* ctx = _ctx;
	FAILIF(keysize != 32, MR_E_INVALIDSIZE, "keysize != 32")
	FAILIF(ivsize != 16, MR_E_INVALIDSIZE, "ivsize != 16")
	FAILIF(!key || !_ctx || !iv, MR_E_INVALIDARG, "!key || !_ctx || !iv")

	uint8_t tkey[32];
	memcpy(tkey, key, 16);
	Aes aes;
	int r = wc_AesSetKeyDirect(&aes, key + 16, 16, 0, AES_ENCRYPTION);
	FAILIF(r != 0, MR_E_INVALIDOP, "r != 0")
	wc_AesEncryptDirect(&aes, tkey + 16, iv);

	r = wc_Poly1305SetKey(&ctx->wc_poly, tkey, 32);
	FAILIF(r != 0, MR_E_INVALIDOP, "r != 0")
	return MR_E_SUCCESS;
}

mr_result mr_poly_process(mr_poly_ctx _ctx, const uint8_t* data, uint32_t amount)
{
	_mr_poly_ctx* ctx = _ctx;
	FAILIF(!amount, MR_E_INVALIDSIZE, "!amount")
	FAILIF(!data || !_ctx, MR_E_INVALIDARG, "!data || !_ctx")

	int r =  wc_Poly1305Update(&ctx->wc_poly, data, amount);
	FAILIF(r != 0, MR_E_INVALIDOP, "r != 0")
	return MR_E_SUCCESS;
}

mr_result mr_poly_compute(mr_poly_ctx _ctx, uint8_t* output, uint32_t spaceavail)
{
	_mr_poly_ctx* ctx = _ctx;
	FAILIF(!spaceavail, MR_E_INVALIDSIZE, "!spaceavail")
	FAILIF(!output || !_ctx, MR_E_INVALIDARG, "!output || !_ctx")

	if (spaceavail < 16)
	{
		uint8_t tmp[16];
		int r = wc_Poly1305Final(&ctx->wc_poly, tmp);
		FAILIF(r != 0, MR_E_INVALIDOP, "r != 0")
		memcpy(output, tmp, spaceavail);
	}
	else if (spaceavail == 16)
	{
		int r = wc_Poly1305Final(&ctx->wc_poly, output);
		FAILIF(r != 0, MR_E_INVALIDOP, "r != 0")
	}
	else
	{
		int r = wc_Poly1305Final(&ctx->wc_poly, output);
		FAILIF(r != 0, MR_E_INVALIDOP, "r != 0")
		memset(output + 16, 0, spaceavail - 16);
	}
	return MR_E_SUCCESS;
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
