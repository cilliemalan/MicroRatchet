#include "pch.h"
#include <microratchet.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>

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

int mr_aes_init(mr_aes_ctx _ctx, const unsigned char* key, unsigned int keysize, const unsigned char* iv, unsigned int ivsize)
{
	_mr_aes_ctx* ctx = _ctx;
	if (keysize != 16 && keysize != 32) return E_INVALIDSIZE;
	if (!key || !iv || !_ctx) return E_INVALIDARGUMENT;

	// trim IV to correct length
	if (ivsize < 16)
	{
		unsigned char niv[16];
		memset(niv, 0, 16);
		memcpy(niv + ivsize, 0, 16 - ivsize);
		int r = wc_AesSetKey(&ctx->wc_aes, key, keysize, niv, AES_ENCRYPTION);
		if (r != 0) return E_INVALIDOP;
	}
	else
	{
		int r = wc_AesSetKey(&ctx->wc_aes, key, keysize, iv, AES_ENCRYPTION);
		if (r != 0) return E_INVALIDOP;
	}

	return E_SUCCESS;
}	

int mr_aes_process(mr_aes_ctx _ctx, const unsigned char* data, unsigned int amount, unsigned char* output, unsigned int spaceavail)
{
	_mr_aes_ctx* ctx = _ctx;
	if (amount > spaceavail) return E_INVALIDSIZE;
	if (!data || !output || !_ctx) return E_INVALIDARGUMENT;

	int r = wc_AesCtrEncrypt(&ctx->wc_aes, output, data, amount);
	if (r != 0) return E_INVALIDOP;
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
