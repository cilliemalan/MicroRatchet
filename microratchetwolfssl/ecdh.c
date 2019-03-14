#include "pch.h"
#include <microratchet.h>

#define HAVE_ECC
#define HAVE_ECC_SIGN
#define HAVE_ECC_VERIFY
#define HAVE_ECC_DHE
#define HAVE_ECC_KEY_IMPORT
#define HAVE_ECC_KEY_EXPORT
#define ECC_SHAMIR
#define HAVE_COMP_KEY
#define USE_ECC_B_PARAM
#include <wolfssl/wolfcrypt/ecc.h>


typedef struct {
	mr_ctx mr_ctx;
	ecc_key key;
} _mr_ecdh_ctx;

mr_ecdh_ctx mr_ecdh_create(mr_ctx mr_ctx)
{
	_mr_ecdh_ctx* ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_ecdh_ctx), &ctx);
	if (r != E_SUCCESS) return 0;

	ctx->mr_ctx = mr_ctx;
	memset(&ctx->key, 0, sizeof(ctx->key));
	return ctx;
}

int mr_ecdh_generate(mr_ecdh_ctx _ctx, unsigned char* publickey, unsigned int publickeyspaceavail, unsigned int* publickeysize)
{
	_mr_ecdh_ctx* ctx = _ctx;
	if (publickeyspaceavail < 32) return E_INVALIDSIZE;
	if (!publickey || !ctx || !publickeysize) return E_INVALIDARGUMENT;

	WC_RNG rng;
	wc_InitRng(&rng);
	int result = wc_ecc_make_key(&rng, 32, &ctx->key);
	if (result != 0) return E_INVALIDOP;
	//mr_ecdh_generate_cb(E_SUCCESS, ctx, ctx->mr_ctx);

	*publickeysize = 32;
	return E_SUCCESS;
}

int mr_ecdh_load(mr_ecdh_ctx ctx, unsigned char* data, unsigned int spaceavail, unsigned int* amountread)
{
	return E_SUCCESS;
}

int mr_ecdh_derivekey(mr_ecdh_ctx ctx, const unsigned char* otherpublickey, unsigned int otherpublickeysize, unsigned char* derivedkey, unsigned int derivedkeyspaceavail, unsigned int* derivedkeysize)
{
	return E_SUCCESS;
}

int mr_ecdh_store_size_needed(mr_ecdh_ctx ctx)
{
	return E_SUCCESS;
}

int mr_ecdh_store(mr_ecdh_ctx ctx, unsigned char* data, unsigned int spaceavail, unsigned int* amountstored)
{
	return E_SUCCESS;
}

void mr_ecdh_destroy(mr_ecdh_ctx ctx)
{
	if (ctx)
	{
		_mr_ecdh_ctx* _ctx = (_mr_ecdh_ctx*)ctx;
		mr_free(_ctx->mr_ctx, _ctx);
	}
}