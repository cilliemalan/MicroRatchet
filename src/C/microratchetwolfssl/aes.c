#include "pch.h"
#include <microratchet.h>
#include <wolfssl/wolfcrypt/aes.h>

typedef struct {
	mr_ctx mr_ctx;
	Aes wc_aes;
} _mr_aes_ctx;

mr_aes_ctx mr_aes_create(mr_ctx mr_ctx)
{
	_mr_aes_ctx* ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_aes_ctx), &ctx);
	if (r != E_SUCCESS) return 0;

	ctx->mr_ctx = mr_ctx;
	memset(&ctx->wc_aes, 0, sizeof(ctx->wc_aes));
	return ctx;
}

mr_result_t mr_aes_init(mr_aes_ctx _ctx, const uint8_t* key, uint32_t keysize)
{
	_mr_aes_ctx* ctx = _ctx;
	if (keysize != 16 && keysize != 24 && keysize != 32) return E_INVALIDSIZE;


	int r = wc_AesSetKeyDirect(&ctx->wc_aes, key, keysize, 0, AES_ENCRYPTION);
	if (r != 0) return E_INVALIDOP;

	return E_SUCCESS;
}	

mr_result_t mr_aes_process(mr_aes_ctx _ctx, const uint8_t* data, uint32_t amount, uint8_t* output, uint32_t spaceavail)
{
	_mr_aes_ctx* ctx = _ctx;
	if (amount > spaceavail) return E_INVALIDSIZE;
	if (!data || !output || !_ctx) return E_INVALIDARGUMENT;
	if (amount < 16 || spaceavail < 16) return E_INVALIDSIZE;

	wc_AesEncryptDirect(&ctx->wc_aes, output, data);
	return E_SUCCESS;
}

void mr_aes_destroy(mr_aes_ctx ctx)
{
	if (ctx)
	{
		_mr_aes_ctx* _ctx = (_mr_aes_ctx*)ctx;
		wc_AesFree(&_ctx->wc_aes);
		mr_free(_ctx->mr_ctx, _ctx);
	}
}
