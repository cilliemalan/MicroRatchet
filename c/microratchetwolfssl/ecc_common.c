#include "pch.h"
#include <microratchet.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>

int mp_sqrtmod_prime(mp_int* n, mp_int* prime, mp_int* ret);

mr_result ecc_import_public(const uint8_t* otherpublickey, uint32_t otherpublickeysize, ecc_point *pub)
{
	const ecc_set_type* dp = &ecc_sets[wc_ecc_get_curve_idx(ECC_SECP256R1)];

	int result = mp_init_multi(pub->x, pub->y, pub->z, 0, 0, 0);
	FAILIF(result != 0, MR_E_INVALIDOP, "result != 0");
	result = mp_set(pub->z, 1);
	FAILIF(result != 0, MR_E_INVALIDOP, "result != 0");

	// load x
	result = mp_read_unsigned_bin(pub->x, otherpublickey, otherpublickeysize);
	FAILIF(result != 0, MR_E_INVALIDOP, "result != 0");

	// allocate variables
	mp_int* vars;
	result = mr_allocate(0, sizeof(mp_int) * 5, (void**)&vars);
	FAILIF(result, result, "Could not allocate 5 mp ints");
	mp_int *p = &vars[0];
	mp_int *a = &vars[1];
	mp_int *b = &vars[2];
	mp_int *t1 = &vars[3];
	mp_int *t2 = &vars[4];


	// derive y from x

	// load curve parameters into numbers we can use
	if (!result) result = mp_init_multi(t1, t2, p, a, b, 0);
	if (!result) result = mp_read_radix(p, dp->prime, MP_RADIX_HEX);
	if (!result) result = mp_read_radix(a, dp->Af, MP_RADIX_HEX);
	if (!result) result = mp_read_radix(b, dp->Bf, MP_RADIX_HEX);

	// t1 = x^3 over p
	if (!result) result = mp_sqr(pub->x, t1);
	if (!result) result = mp_mulmod(t1, pub->x, p, t1);

	// t1 = t1 + a*x over p
	if (!result) result = mp_mulmod(a, pub->x, p, t2);
	if (!result) result = mp_add(t1, t2, t1);

	// t1 = t1 + b
	if (!result) result = mp_add(t1, b, t1);

	// t2 = sqrt(t1) over p
	if (!result) result = mp_sqrtmod_prime(t1, p, t2);

	// set y. and fix if not even
	if (!result)
	{
		if (mp_isodd(t2) == MP_NO)
		{
			// y = t2 over p
			result = mp_mod(t2, p, pub->y);
		}
		else
		{
			// y = (p - t2) over p
			result = mp_submod(p, t2, p, pub->y);
		}
	}

	mr_free(0, vars);

	FAILIF(result != 0, MR_E_INVALIDOP, "result != 0");

	return MR_E_SUCCESS;
}


mr_result ecc_generate(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	FAILIF(!key, MR_E_INVALIDARG, "!key");

	WC_RNG rng;
	int result = wc_InitRng(&rng);
	FAILIF(result != 0, MR_E_INVALIDOP, "result != 0");
	uint32_t pubkeylen = 0;
	for (;;)
	{
		result = wc_ecc_make_key_ex(&rng, 32, key, ECC_SECP256R1);
		FAILIF(result != 0, MR_E_INVALIDOP, "result != 0");

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

	if (publickey && publickeyspaceavail)
	{
		result = mp_to_unsigned_bin(key->pubkey.x, publickey + (32 - pubkeylen));
		if (pubkeylen < 32) memset(publickey, 0, 32 - pubkeylen);
		FAILIF(result != 0, MR_E_INVALIDOP, "result != 0");
	}

	return MR_E_SUCCESS;
}

uint32_t ecc_load(ecc_key* key, const uint8_t* data, uint32_t spaceavail)
{
	memset(key , 0, sizeof(ecc_key));

	if (spaceavail < 32) return 0;
	int result = wc_ecc_import_private_key_ex(data, 32, 0, 0, key, ECC_SECP256R1);
	if (result != 0) return 0;
	return 32;
}

mr_result ecc_store_size_needed(const ecc_key* key)
{
	return 32;
}

mr_result ecc_store(const ecc_key* key, uint8_t* data, uint32_t spaceavail)
{
	FAILIF(!key || !data, MR_E_INVALIDARG, "!key || !data");
	FAILIF(spaceavail < 32, MR_E_INVALIDSIZE, "spaceavail < 32");

	int len = mp_unsigned_bin_size((mp_int*)&key->k);
	FAILIF(len < 0 || (uint32_t)len > 32, MR_E_INVALIDSIZE, "len < 0 || (uint32_t)len > 32");
	int offset = 32 - len;
	int r = mp_to_unsigned_bin((mp_int*)&key->k, data + offset);
	FAILIF(r != 0, MR_E_INVALIDOP, "r != 0");
	return MR_E_SUCCESS;
}

mr_result ecc_sign(const ecc_key *key, const uint8_t* digest, uint32_t digestsize, uint8_t* signature, uint32_t signaturespaceavail)
{
	FAILIF(!key || !digest || !signature, MR_E_INVALIDARG, "!key || !digest || !signature");
	FAILIF(signaturespaceavail < 64, MR_E_INVALIDSIZE, "signaturespaceavail < 64");

	WC_RNG rng;
	int result = wc_InitRng(&rng);
	FAILIF(result != 0, MR_E_INVALIDOP, "result != 0");

	mp_int r, s;
	result = mp_init_multi(&r, &s, 0, 0, 0, 0);
	FAILIF(result != 0, MR_E_INVALIDOP, "result != 0");
	result = wc_ecc_sign_hash_ex(digest, digestsize, &rng, (ecc_key*)key, &r, &s);
	FAILIF(result != 0, MR_E_INVALIDOP, "result != 0");
	uint32_t l = (uint32_t)mp_unsigned_bin_size(&r);
	FAILIF(l > 32, MR_E_INVALIDOP, "l > 32");
	result = mp_to_unsigned_bin(&r, signature + (32 - l));
	if (l < 32) memset(signature, 0, 32 - l);
	FAILIF(result != 0, MR_E_INVALIDOP, "result != 0");
	l = mp_unsigned_bin_size(&s);
	FAILIF(l > 32, MR_E_INVALIDOP, "l > 32");
	result = mp_to_unsigned_bin(&s, signature + (64 - l));
	if (l < 32) memset(signature + 32, 0, 32 - l);
	FAILIF(result != 0, MR_E_INVALIDOP, "result != 0");

	return MR_E_SUCCESS;
}

mr_result ecc_verify(const ecc_key *key, const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, uint32_t* result)
{
	FAILIF(!key || !digest || !signature || !signaturesize, MR_E_INVALIDARG, "!key || !digest || !signature || !signaturesize");
	FAILIF(signaturesize != 64, MR_E_INVALIDSIZE, "signaturesize != 64");

	mp_int r, s;
	int res = mp_init_multi(&r, &s, 0, 0, 0, 0);
	FAILIF(res != 0, MR_E_INVALIDOP, "res != 0");
	res = mp_read_unsigned_bin(&r, signature, 32);
	FAILIF(res != 0, MR_E_INVALIDOP, "res != 0");
	res = mp_read_unsigned_bin(&s, signature + 32, 32);
	FAILIF(res != 0, MR_E_INVALIDOP, "res != 0");

	int wcresult;
	res = wc_ecc_verify_hash_ex(&r, &s, digest, digestsize, &wcresult, (ecc_key*)key);
	if (result) *result = !!wcresult;
	FAILIF(res != 0, MR_E_INVALIDOP, "res != 0");

	return MR_E_SUCCESS;
}

mr_result ecc_getpublickey(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	FAILIF(!key || !publickey, MR_E_INVALIDARG, "!key || !publickey");
	FAILIF(publickeyspaceavail < 32, MR_E_INVALIDSIZE, "publickeyspaceavail < 32");
	int result = 0;

	if (key->type == ECC_PRIVATEKEY_ONLY)
	{
		// we mutate but pointer is opaque
		result = wc_ecc_make_pub(key, &key->pubkey);
		key->type = ECC_PRIVATEKEY;
	}
	else if (key->type == ECC_PUBLICKEY)
	{
		return MR_E_INVALIDARG;
	}

	uint32_t pubkeylen = (uint32_t)mp_unsigned_bin_size(key->pubkey.x);
	result = mp_to_unsigned_bin(key->pubkey.x, publickey + (32 - pubkeylen));
	if (pubkeylen < 32) memset(publickey, 0, 32 - pubkeylen);
	FAILIF(result != 0, MR_E_INVALIDOP, "result != 0");
	return MR_E_SUCCESS;
}
