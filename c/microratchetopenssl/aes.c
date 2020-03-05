#include "pch.h"
#include <microratchet.h>
#include <openssl/aes.h>

typedef struct {
	mr_ctx mr_ctx;
	AES_KEY aes;
} _mr_aes_ctx;

mr_aes_ctx mr_aes_create(mr_ctx mr_ctx)
{
	_mr_aes_ctx* ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_aes_ctx), (void**)&ctx);
	if (r != MR_E_SUCCESS) return 0;
	*ctx = (_mr_aes_ctx){
		.mr_ctx = mr_ctx,
		.aes = {0}
	};
	return ctx;
}

mr_result mr_aes_init(mr_aes_ctx _ctx, const uint8_t* key, uint32_t keysize)
{
	_mr_aes_ctx* ctx = _ctx;
	FAILIF(!ctx, MR_E_INVALIDARG, "ctx must not be null");
	FAILIF(!key, MR_E_INVALIDARG, "key must not be null");
	FAILIF(keysize != 16 && keysize != 24 && keysize != 32, MR_E_INVALIDSIZE, "keysize != 16 && keysize != 24 && keysize != 32");

	int r = AES_set_encrypt_key(key, keysize * 8, &ctx->aes);
	FAILIF(r != 0, MR_E_INVALIDOP, "Could not set AES key");

	return MR_E_SUCCESS;
}

mr_result mr_aes_process(mr_aes_ctx _ctx, const uint8_t* data, uint32_t amount, uint8_t* output, uint32_t spaceavail)
{
	_mr_aes_ctx* ctx = _ctx;
	FAILIF(amount > spaceavail, MR_E_INVALIDSIZE, "amount > spaceavail");
	FAILIF(!data || !output || !_ctx, MR_E_INVALIDARG, "!data || !output || !_ctx");
	FAILIF(amount < 16 || spaceavail < 16, MR_E_INVALIDSIZE, "amount < 16 || spaceavail < 16");

	AES_encrypt(data, output, &ctx->aes);

	return MR_E_SUCCESS;
}

void mr_aes_destroy(mr_aes_ctx ctx)
{
	if (ctx)
	{
		_mr_aes_ctx* _ctx = (_mr_aes_ctx*)ctx;

		*_ctx = (_mr_aes_ctx){ 0 };
		mr_free(_ctx->mr_ctx, _ctx);
	}
}
