#include "pch.h"
#include <microratchet.h>
#include <mbedtls/poly1305.h>
#include <mbedtls/aes.h>

#include <memory.h>

//Poly1305

typedef struct {
	mr_ctx mr_ctx;
	mbedtls_poly1305_context poly_ctx;
} _mr_poly_ctx;

mr_poly_ctx mr_poly_create(mr_ctx mr_ctx)
{
	_mr_poly_ctx* ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_poly_ctx), (void**)&ctx);
	if (r != MR_E_SUCCESS) return 0;

	ctx->mr_ctx = mr_ctx;
	mbedtls_poly1305_init(&ctx->poly_ctx);
	return ctx;
}

mr_result mr_poly_init(mr_poly_ctx _ctx, const uint8_t* key, uint32_t keysize, const uint8_t* iv, uint32_t ivsize)
{
	_mr_poly_ctx* ctx = _ctx;
	FAILIF(keysize != 32, MR_E_INVALIDSIZE, "keysize != 32");
	FAILIF(ivsize != 16, MR_E_INVALIDSIZE, "ivsize != 16");
	FAILIF(!key || !_ctx || !iv, MR_E_INVALIDARG, "!key || !_ctx || !iv");

	uint8_t tkey[32];
	mr_memcpy(tkey, key, 16);
	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);
	int r = mbedtls_aes_setkey_enc(&aes, key + 16, 16 * 8);
	FAILIF(r, MR_E_INVALIDOP, "Failed to init AES during poly1305 init");
	r = mbedtls_internal_aes_encrypt(&aes, iv, tkey + 16);
	FAILIF(r, MR_E_INVALIDOP, "Failed to crypt AES during poly1305 init");
	r = mbedtls_poly1305_starts(&ctx->poly_ctx, tkey);
	FAILIF(r, MR_E_INVALIDOP, "Failed to init poly1305");

	return MR_E_SUCCESS;
}

mr_result mr_poly_process(mr_poly_ctx _ctx, const uint8_t* data, uint32_t amount)
{
	_mr_poly_ctx* ctx = _ctx;
	FAILIF(!amount, MR_E_INVALIDSIZE, "!amount");
	FAILIF(!data || !_ctx, MR_E_INVALIDARG, "!data || !_ctx");

	int r = mbedtls_poly1305_update(&ctx->poly_ctx, data, amount);
	FAILIF(r, MR_E_INVALIDOP, "Failed to process poly1305");

	return MR_E_SUCCESS;
}

mr_result mr_poly_compute(mr_poly_ctx _ctx, uint8_t* output, uint32_t spaceavail)
{
	_mr_poly_ctx* ctx = _ctx;
	FAILIF(!spaceavail, MR_E_INVALIDSIZE, "!spaceavail");
	FAILIF(!output || !_ctx, MR_E_INVALIDARG, "!output || !_ctx");

	uint8_t tmp[16];
	int r = mbedtls_poly1305_finish(&ctx->poly_ctx, tmp);
	FAILIF(r, MR_E_INVALIDOP, "Failed to finish poly1305");
	mr_memcpy(output, tmp, spaceavail < 16 ? spaceavail : 16);

	return MR_E_SUCCESS;
}

void mr_poly_destroy(mr_poly_ctx ctx)
{
	if (ctx)
	{
		_mr_poly_ctx* _ctx = (_mr_poly_ctx*)ctx;
		mr_ctx mrctx = _ctx->mr_ctx;
		mr_memzero(_ctx, sizeof(_mr_poly_ctx));
		mr_free(mrctx, _ctx);
	}
}
