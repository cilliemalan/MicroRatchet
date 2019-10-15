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
	if (r != MR_E_SUCCESS) return 0;

	ctx->mr_ctx = mr_ctx;
	memset(&ctx->wc_aes, 0, sizeof(ctx->wc_aes));
	return ctx;
}

mr_result_t mr_aes_init(mr_aes_ctx _ctx, const uint8_t* key, uint32_t keysize)
{
	_mr_aes_ctx* ctx = _ctx;
	FAILIF(keysize != 16 && keysize != 24 && keysize != 32, MR_E_INVALIDSIZE, "keysize != 16 && keysize != 24 && keysize != 32")


	int r = wc_AesSetKeyDirect(&ctx->wc_aes, key, keysize, 0, AES_ENCRYPTION);
	FAILIF(r != 0, MR_E_INVALIDOP, "r != 0")

	return MR_E_SUCCESS;
}	

mr_result_t mr_aes_process(mr_aes_ctx _ctx, const uint8_t* data, uint32_t amount, uint8_t* output, uint32_t spaceavail)
{
	_mr_aes_ctx* ctx = _ctx;
	FAILIF(amount > spaceavail, MR_E_INVALIDSIZE, "amount > spaceavail")
	FAILIF(!data || !output || !_ctx, MR_E_INVALIDARG, "!data || !output || !_ctx")
	FAILIF(amount < 16 || spaceavail < 16, MR_E_INVALIDSIZE, "amount < 16 || spaceavail < 16")

	wc_AesEncryptDirect(&ctx->wc_aes, output, data);
	return MR_E_SUCCESS;
}

void mr_aes_destroy(mr_aes_ctx ctx)
{
	if (ctx)
	{
		_mr_aes_ctx* _ctx = (_mr_aes_ctx*)ctx;
		wc_AesFree(&_ctx->wc_aes);
		*_ctx = (_mr_aes_ctx){ 0 };
		mr_free(_ctx->mr_ctx, _ctx);
	}
}
