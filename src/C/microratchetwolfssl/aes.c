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

	// IV must always be hashed
	unsigned char hashediv[32];
	{
		Sha256 sha;
		memset(&sha, 0, sizeof(sha));
		wc_InitSha256(&sha);
		wc_Sha256Update(&sha, iv, ivsize);
		wc_Sha256Final(&sha, hashediv);
		wc_Sha256Free(&sha);
	}

	int r = wc_AesSetKey(&ctx->wc_aes, key, keysize, hashediv, AES_ENCRYPTION);
	if (r != 0) return E_INVALIDOP;
	mr_aes_init_cb(E_SUCCESS, _ctx, ctx->mr_ctx);
	return E_SUCCESS;
}	

int mr_aes_process(mr_aes_ctx _ctx, const unsigned char* data, unsigned int amount, unsigned char* output, unsigned int spaceavail)
{
	_mr_aes_ctx* ctx = _ctx;
	if (amount > spaceavail) return E_INVALIDSIZE;
	if (!data || !output || !_ctx) return E_INVALIDARGUMENT;

	int r = wc_AesCtrEncrypt(&ctx->wc_aes, output, data, amount);
	if (r != 0) return E_INVALIDOP;
	mr_aes_process_cb(E_SUCCESS, _ctx, ctx->mr_ctx);
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
