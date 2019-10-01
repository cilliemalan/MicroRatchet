#include "pch.h"
#include <microratchet.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>


int mp_sqrtmod_prime(mp_int* n, mp_int* prime, mp_int* ret);

mr_result_t ecc_import_public(const uint8_t* otherpublickey, uint32_t otherpublickeysize, ecc_point *pub)
{
	const ecc_set_type* dp = &ecc_sets[wc_ecc_get_curve_idx(ECC_SECP256R1)];

	int result = mp_init_multi(pub->x, pub->y, pub->z, 0, 0, 0);
	if (result != 0) return E_INVALIDOP;
	result = mp_set(pub->z, 1);
	if (result != 0) return E_INVALIDOP;

	// load x
	result = mp_read_unsigned_bin(pub->x, otherpublickey, otherpublickeysize);
	if (result != 0) return E_INVALIDOP;

	// derive y from x

	// load curve parameters into numbers we can use
	mp_int p, a, b;
	mp_int t1, t2;
	result = mp_init_multi(&t1, &t2, &p, &a, &b, 0);
	result = mp_read_radix(&p, dp->prime, MP_RADIX_HEX);
	if (result != 0) return E_INVALIDOP;
	result = mp_read_radix(&a, dp->Af, MP_RADIX_HEX);
	if (result != 0) return E_INVALIDOP;
	result = mp_read_radix(&b, dp->Bf, MP_RADIX_HEX);
	if (result != 0) return E_INVALIDOP;

	// t1 = x^3 over p
	result = mp_sqr(pub->x, &t1);
	if (result != 0) return E_INVALIDOP;
	result = mp_mulmod(&t1, pub->x, &p, &t1);
	if (result != 0) return E_INVALIDOP;

	// t1 = t1 + a*x over p
	result = mp_mulmod(&a, pub->x, &p, &t2);
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
		result = mp_mod(&t2, &p, pub->y);
	}
	else
	{
		// y = (p - t2) over p
		result = mp_submod(&p, &t2, &p, pub->y);
	}
	if (result != 0) return E_INVALIDOP;

	return E_SUCCESS;
}


mr_result_t ecc_generate(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	if (publickeyspaceavail < 32) return E_INVALIDSIZE;
	if (!publickey || !key) return E_INVALIDARGUMENT;

	WC_RNG rng;
	int result = wc_InitRng(&rng);
	if (result != 0) return E_INVALIDOP;
	uint32_t pubkeylen = 0;
	for (;;)
	{
		result = wc_ecc_make_key_ex(&rng, 32, key, ECC_SECP256R1);
		if (result != 0) return E_INVALIDOP;

		// try until we have a private key with an even public key y component.
		if (mp_iseven(key->pubkey.y))
		{
			// try until the public key x component is under or at 256 bits.
			pubkeylen = (uint32_t)mp_unsigned_bin_size(key->pubkey.x);
			if (pubkeylen <= 32)
			{
				break;
			}
		}
	}

	result = mp_to_unsigned_bin(key->pubkey.x, publickey + (32 - pubkeylen));
	if (pubkeylen < 32) memset(publickey, 0, 32 - pubkeylen);
	if (result != 0) return E_INVALIDOP;

	return E_SUCCESS;
}

mr_result_t ecc_load(ecc_key* key, const uint8_t* data, uint32_t spaceavail)
{
	memset(key, 0, sizeof(ecc_key));

	int result = wc_ecc_import_private_key_ex(data, spaceavail, 0, 0, key, ECC_SECP256R1);
	if (result != 0) return E_INVALIDOP;

	return E_SUCCESS;
}

mr_result_t ecc_store_size_needed(const mp_int* key)
{
	return mp_unsigned_bin_size((mp_int*)key);
}

mr_result_t ecc_store(const ecc_key* key, uint8_t* data, uint32_t spaceavail)
{
	if (!key || !data) return E_INVALIDARGUMENT;
	if (spaceavail < 32) return E_INVALIDSIZE;

	int len = mp_unsigned_bin_size((mp_int*)&key->k);
	if (len < 0 || (uint32_t)len > 32) return E_INVALIDSIZE;
	int r = mp_to_unsigned_bin((mp_int*)&key->k, data);
	if (r != 0) return E_INVALIDOP;
	return E_SUCCESS;
}

mr_result_t ecc_sign(const ecc_key *key, const uint8_t* digest, uint32_t digestsize, uint8_t* signature, uint32_t signaturespaceavail)
{
	if (!key || !digest || !signature) return E_INVALIDARGUMENT;
	if (signaturespaceavail < 64) return E_INVALIDSIZE;

	WC_RNG rng;
	int result = wc_InitRng(&rng);
	if (result != 0) return E_INVALIDOP;

	mp_int r, s;
	result = mp_init_multi(&r, &s, 0, 0, 0, 0);
	if (result != 0) return E_INVALIDOP;
	result = wc_ecc_sign_hash_ex(digest, digestsize, &rng, (ecc_key*)key, &r, &s);
	if (result != 0) return E_INVALIDOP;
	uint32_t l = (uint32_t)mp_unsigned_bin_size(&r);
	if (l > 32) return E_INVALIDOP;
	result = mp_to_unsigned_bin(&r, signature + (32 - l));
	if (l < 32) memset(signature, 0, 32 - l);
	if (result != 0) return E_INVALIDOP;
	l = mp_unsigned_bin_size(&s);
	if (l > 32) return E_INVALIDOP;
	result = mp_to_unsigned_bin(&s, signature + (64 - l));
	if (l < 32) memset(signature + 32, 0, 32 - l);
	if (result != 0) return E_INVALIDOP;

	return E_SUCCESS;
}

mr_result_t ecc_verify(const ecc_key *key, const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, uint32_t* result)
{
	if (!key || !digest || !signature || !signaturesize) return E_INVALIDARGUMENT;
	if (signaturesize != 64) return E_INVALIDSIZE;

	mp_int r, s;
	int res = mp_init_multi(&r, &s, 0, 0, 0, 0);
	if (res != 0) return E_INVALIDOP;
	res = mp_read_unsigned_bin(&r, signature, 32);
	if (res != 0) return E_INVALIDOP;
	res = mp_read_unsigned_bin(&s, signature + 32, 32);
	if (res != 0) return E_INVALIDOP;


	res = wc_ecc_verify_hash_ex(&r, &s, digest, digestsize, result, (ecc_key*)key);
	if (res != 0) return E_INVALIDOP;

	return E_SUCCESS;
}

mr_result_t ecc_getpublickey(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	if (!key || !publickey) return E_INVALIDARGUMENT;
	if (publickeyspaceavail < 32) return E_INVALIDSIZE;
	int result = 0;

	if (key->type == ECC_PRIVATEKEY_ONLY)
	{
		// we mutate but pointer is opaque
		result = wc_ecc_make_pub(key, &key->pubkey);
		key->type = ECC_PRIVATEKEY;
	}
	else if (key->type == ECC_PUBLICKEY)
	{
		return E_INVALIDARGUMENT;
	}

	uint32_t pubkeylen = (uint32_t)mp_unsigned_bin_size(key->pubkey.x);
	result = mp_to_unsigned_bin(key->pubkey.x, publickey + (32 - pubkeylen));
	if (pubkeylen < 32) memset(publickey, 0, 32 - pubkeylen);
	if (result != 0) return E_INVALIDOP;
	return E_SUCCESS;
}