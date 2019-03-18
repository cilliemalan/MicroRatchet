#include "pch.h"
#include <microratchet.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>

int mp_sqrtmod_prime(mp_int* n, mp_int* prime, mp_int* ret);

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
	int result = mp_init_multi(pub.x, pub.y, pub.z, 0, 0, 0);
	if (result != 0) return E_INVALIDOP;
	result = mp_set(pub.z, 1);
	if (result != 0) return E_INVALIDOP;

	result = mp_read_unsigned_bin(pub.x, otherpublickey, otherpublickeysize);
	if (result != 0) return E_INVALIDOP;

	// derive y from x
	{
		// load curve parameters into numbers we can use
		mp_int p, a, b;
		mp_int t1, t2;
		result = mp_init_multi(&t1, &t2, &p, &a, &b, 0);
		result = mp_read_radix(&p, ctx->key.dp->prime, MP_RADIX_HEX);
		if (result != 0) return E_INVALIDOP;
		result = mp_read_radix(&a, ctx->key.dp->Af, MP_RADIX_HEX);
		if (result != 0) return E_INVALIDOP;
		result = mp_read_radix(&b, ctx->key.dp->Bf, MP_RADIX_HEX);
		if (result != 0) return E_INVALIDOP;


		// t1 = x^3 over p
		result = mp_sqr(pub.x, &t1);
		if (result != 0) return E_INVALIDOP;
		result = mp_mulmod(&t1, pub.x, &p, &t1);
		if (result != 0) return E_INVALIDOP;

		// t1 = t1 + a*x over p
		result = mp_mulmod(&a, pub.x, &p, &t2);
		if (result != 0) return E_INVALIDOP;
		result = mp_add(&t1, &t2, &t1);
		if (result != 0) return E_INVALIDOP;

		// t1 = t1 + b
		result = mp_add(&t1, &b, &t1);
		if (result != 0) return E_INVALIDOP;

		// t2 = sqrt(t1) over p
		result = mp_sqrtmod_prime(&t1, &p, &t2);
		if (result != 0) return E_INVALIDOP;

		// set y. and fix if not even
		if (mp_isodd(&t2) == MP_NO)
		{
			// y = t2 over p
			result = mp_mod(&t2, &p, pub.y);
		}
		else
		{
			// y = (p - t2) over p
			result = mp_submod(&p, &t2, &p, pub.y);
		}
		if (result != 0) return E_INVALIDOP;
	}

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