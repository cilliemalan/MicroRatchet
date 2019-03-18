#include "pch.h"
#include <microratchet.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include "ecc_common.h"

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
	int result = wc_InitRng(&rng);
	if (result != 0) return E_INVALIDOP;
	int pubkeylen = 0;
	for (;;)
	{
		result = wc_ecc_make_key_ex(&rng, 32, &ctx->key, ECC_SECP256R1);
		if (result != 0) return E_INVALIDOP;

		// try until we have a private key with an even public key y component.
		if (mp_iseven(ctx->key.pubkey.y))
		{
			// try until the public key x component is under or at 256 bits.
			pubkeylen = mp_unsigned_bin_size(ctx->key.pubkey.x);
			if (pubkeylen <= 32)
			{
				break;
			}
		}
	}

	memset(publickey, 0, 32);
	result = mp_to_unsigned_bin(ctx->key.pubkey.x, publickey + (32 - pubkeylen));
	if (result != 0) return E_INVALIDOP;
	*publickeysize = 32;

	mr_ecdh_generate_cb(E_SUCCESS, ctx, ctx->mr_ctx);
	return E_SUCCESS;
}

int mr_ecdh_load(mr_ecdh_ctx _ctx, unsigned char* data, unsigned int spaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;
	ecc_key* key = &ctx->key;
	memset(key, 0, sizeof(ctx->key));

	int result = wc_ecc_import_private_key_ex(data, spaceavail, 0, 0, key, ECC_SECP256R1);
	if (result != 0) return E_INVALIDOP;

	mr_ecdh_load_cb(E_SUCCESS, ctx, ctx->mr_ctx);
	return E_SUCCESS;
}

int mr_ecdh_derivekey(mr_ecdh_ctx _ctx, const unsigned char* otherpublickey, unsigned int otherpublickeysize, unsigned char* derivedkey, unsigned int derivedkeyspaceavail, unsigned int* derivedkeysize)
{
	_mr_ecdh_ctx* ctx = _ctx;
	if (!ctx || !otherpublickey || !derivedkey || !derivedkeysize) return E_INVALIDARG;
	if (otherpublickeysize != 32) return E_INVALIDSIZE;
	if (derivedkeyspaceavail < 32) return E_INVALIDSIZE;

	ecc_point pub;
	int result = ecc_import_public(otherpublickey, otherpublickeysize, &pub);
	if (result != 0) return E_INVALIDOP;

	result = wc_ecc_shared_secret_ex(&ctx->key, &pub, derivedkey, derivedkeysize);
	if (result != 0) return E_INVALIDOP;

	mr_ecdh_derivekey_cb(E_SUCCESS, ctx, ctx->mr_ctx);
	return E_SUCCESS;
}

int mr_ecdh_store_size_needed(mr_ecdh_ctx _ctx)
{
	_mr_ecdh_ctx* ctx = _ctx;
	return mp_unsigned_bin_size(ctx->key.pubkey.x);
}

int mr_ecdh_store(mr_ecdh_ctx _ctx, unsigned char* data, unsigned int spaceavail, unsigned int* amountstored)
{
	_mr_ecdh_ctx* ctx = _ctx;
	int len = mp_unsigned_bin_size(ctx->key.pubkey.x);
	if (len < 0 || (unsigned int)len > spaceavail) return E_INVALIDSIZE;
	int r = mp_to_unsigned_bin(&ctx->key.k, data);
	if (r != 0) return E_INVALIDOP;

	*amountstored = (unsigned int)len;

	mr_ecdh_store_cb(E_SUCCESS, ctx, ctx->mr_ctx);
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