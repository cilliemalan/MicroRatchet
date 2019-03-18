#include "pch.h"
#include <microratchet.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>


int mp_sqrtmod_prime(mp_int* n, mp_int* prime, mp_int* ret);

int ecc_import_public(const unsigned char* otherpublickey, unsigned int otherpublickeysize, ecc_point *pub)
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


int ecc_generate(ecc_key* key, unsigned char* publickey, unsigned int publickeyspaceavail, unsigned int* publickeysize)
{
	if (publickeyspaceavail < 32) return E_INVALIDSIZE;
	if (!publickey || !key || !publickeysize) return E_INVALIDARGUMENT;

	WC_RNG rng;
	int result = wc_InitRng(&rng);
	if (result != 0) return E_INVALIDOP;
	int pubkeylen = 0;
	for (;;)
	{
		result = wc_ecc_make_key_ex(&rng, 32, key, ECC_SECP256R1);
		if (result != 0) return E_INVALIDOP;

		// try until we have a private key with an even public key y component.
		if (mp_iseven(key->pubkey.y))
		{
			// try until the public key x component is under or at 256 bits.
			pubkeylen = mp_unsigned_bin_size(key->pubkey.x);
			if (pubkeylen <= 32)
			{
				break;
			}
		}
	}

	memset(publickey, 0, 32);
	result = mp_to_unsigned_bin(key->pubkey.x, publickey + (32 - pubkeylen));
	if (result != 0) return E_INVALIDOP;
	*publickeysize = 32;

	return E_SUCCESS;
}

int ecc_load(ecc_key* key, unsigned char* data, unsigned int spaceavail)
{
	memset(key, 0, sizeof(ecc_key));

	int result = wc_ecc_import_private_key_ex(data, spaceavail, 0, 0, key, ECC_SECP256R1);
	if (result != 0) return E_INVALIDOP;

	return E_SUCCESS;
}

int ecc_store_size_needed(const mp_int* key)
{
	return mp_unsigned_bin_size((mp_int*)key);
}

int ecc_store(const ecc_key* key, unsigned char* data, unsigned int spaceavail, unsigned int* amountstored)
{
	int len = mp_unsigned_bin_size((mp_int*)&key->k);
	if (len < 0 || (unsigned int)len > spaceavail) return E_INVALIDSIZE;
	int r = mp_to_unsigned_bin((mp_int*)&key->k, data);
	if (r != 0) return E_INVALIDOP;
	*amountstored = (unsigned int)len;
	return E_SUCCESS;
}