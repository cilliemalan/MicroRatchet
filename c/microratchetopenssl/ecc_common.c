#include "pch.h"
#include <microratchet.h>
#include "ecc_common.h"
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

static EC_GROUP* g_secp256r1 = 0;


mr_result ecc_new(ecc_key* key)
{
	if (!g_secp256r1) g_secp256r1 = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	FAILIF(!g_secp256r1, MR_E_NOMEM, "could not get p256 group");
	FAILIF(!key, MR_E_INVALIDARG, "key cannot be null");

	key->key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	FAILIF(!key->key, MR_E_NOMEM, "Could not allocate EC key");
	return MR_E_SUCCESS;
}

mr_result ecc_new_point(ecc_point* point)
{
	FAILIF(!point, MR_E_INVALIDARG, "point cannot be null");

	point->point = EC_POINT_new(g_secp256r1);
	FAILIF(!point->point, MR_E_NOMEM, "Could not allocate EC point");
	return MR_E_SUCCESS;
}

mr_result ecc_import_public(const uint8_t* otherpublickey, uint32_t otherpublickeysize, ecc_point* pub)
{
	FAILIF(!otherpublickey, MR_E_INVALIDARG, "!otherpublickey");
	FAILIF(!pub, MR_E_INVALIDARG, "!pub");
	FAILIF(otherpublickeysize != 32, MR_E_INVALIDSIZE, "other public key must be 32 bytes");

	BIGNUM* x = BN_bin2bn(otherpublickey, 32, 0);
	int success = !!x;

	if (success) success = EC_POINT_set_compressed_coordinates(g_secp256r1, pub->point, x, 1, NULL);

	if (x) BN_free(x);

	FAILIF(!success, MR_E_INVALIDOP, "Failed to decode public key");

	return MR_E_SUCCESS;
}

mr_result ecc_generate(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	FAILIF(!key, MR_E_INVALIDARG, "!key");
	FAILIF(!key->key, MR_E_INVALIDARG, "!key->key");
	FAILIF(publickey && publickeyspaceavail < 32, MR_E_INVALIDSIZE, "Need 32 bytes for public key");

	BIGNUM* x = BN_new();
	BIGNUM* y = BN_new();
	//BN_CTX* bnc = BN_CTX_new();

	int success = x && y;

	while (success)
	{
		// generate key
		success = EC_KEY_generate_key(key->key);

		// get public
		const EC_POINT* pub;
		if (success)
		{
			pub = EC_KEY_get0_public_key(key->key);
			success = !!pub;
		}

		// extract coords
		if (success) success = EC_POINT_get_affine_coordinates(g_secp256r1, pub, x, y, NULL);

		// check for evenness. All keys must be even
		if (!success || !BN_is_odd(y)) break;
	}

	// store the public key x coordinate if needed
	if (publickey && success) success = BN_bn2binpad(x, publickey + (32 - publickeyspaceavail), 32);

	// free stuff
	if (x) BN_free(x);
	if (y) BN_free(y);
	//BN_CTX_free(bnc);

	FAILIF(!success, MR_E_INVALIDOP, "Could not generate key pair");
	return MR_E_SUCCESS;
}

uint32_t ecc_load(ecc_key* key, const uint8_t* data, uint32_t size)
{
	FAILIF(!key, MR_E_INVALIDARG, "!key");
	FAILIF(!key->key, MR_E_INVALIDARG, "!key->key");
	FAILIF(!data, MR_E_INVALIDARG, "!data");
	FAILIF(size < 32, MR_E_INVALIDARG, "size must be at least 32 bytes");

	BIGNUM* d = 0;
	EC_POINT* p = 0;

	// allocate
	int success = true;
	d = BN_bin2bn(data, size, 0);
	p = EC_POINT_new(g_secp256r1);
	success = d && p;

	// derive public key
	if (success) success = EC_POINT_mul(g_secp256r1, p, d, NULL, NULL, NULL);

	// load keys
	if (success) success = EC_KEY_set_private_key(key->key, d);
	if (success) success = EC_KEY_set_public_key(key->key, p);

	// free
	if (d) BN_free(d);
	if (p) EC_POINT_free(p);

	return success ? 32 : 0;
}

mr_result ecc_store_size_needed(const ecc_key* key)
{
	return 32;
}

mr_result ecc_store(const ecc_key* key, uint8_t* data, uint32_t spaceavail)
{
	FAILIF(!key || !data, MR_E_INVALIDARG, "!key || !data");
	FAILIF(!key->key, MR_E_INVALIDARG, "!key->key");
	FAILIF(spaceavail < 32, MR_E_INVALIDSIZE, "spaceavail < 32");

	const BIGNUM* d = EC_KEY_get0_private_key(key->key);
	int success = !!d;

	if (success) success = BN_bn2binpad(d, data, 32);

	FAILIF(!success, MR_E_INVALIDOP, "Failed to store private key");
	return MR_E_SUCCESS;
}

mr_result ecc_sign(const ecc_key* key, const uint8_t* digest, uint32_t digestsize, uint8_t* signature, uint32_t signaturespaceavail)
{
	FAILIF(!key || !digest || !signature, MR_E_INVALIDARG, "!key || !digest || !signature");
	FAILIF(!key->key, MR_E_INVALIDARG, "!key->key");
	FAILIF(signaturespaceavail < 64, MR_E_INVALIDSIZE, "signaturespaceavail < 64");

	ECDSA_SIG* sig = ECDSA_do_sign(digest, digestsize, key->key);
	FAILIF(!sig, MR_E_INVALIDOP, "Failed to sign");

	const BIGNUM* r = ECDSA_SIG_get0_r(sig);
	const BIGNUM* s = ECDSA_SIG_get0_s(sig);
	int success = r && s;

	if (success) success = BN_bn2binpad(r, signature, 32);
	if (success) success = BN_bn2binpad(s, signature + 32, 32);

	if (sig) ECDSA_SIG_free(sig);

	FAILIF(!success, MR_E_INVALIDOP, "Failed extract signature");
	return MR_E_SUCCESS;
}

mr_result ecc_verify(const ecc_point* pub, const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, uint32_t* result)
{
	FAILIF(!pub || !digest || !signature || !signaturesize, MR_E_INVALIDARG, "!key || !digest || !signature || !signaturesize");
	FAILIF(!pub->point, MR_E_INVALIDARG, "!pub->point");
	FAILIF(signaturesize != 64, MR_E_INVALIDSIZE, "signaturesize != 64");

	// not efficient but won't break down the line.
	// we don't have a mutable interface to the r and s inside sig
	// so we allocate duplicates and free when we set.
	BIGNUM* r = BN_bin2bn(signature, 32, 0);
	BIGNUM* s = BN_bin2bn(signature + 32, 32, 0);
	ECDSA_SIG* sig = ECDSA_SIG_new();
	EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	int success = r && s && sig && key;

	if (success) success = EC_KEY_set_public_key(key, pub->point);
	if (success) success = ECDSA_SIG_set0(sig, r, s);
	if (success)
	{
		success = ECDSA_do_verify(digest, digestsize, sig, key);
		if (result && success >= 0) *result = success;
		success = success >= 0;
	}

	// this frees r and s as well
	if (sig) ECDSA_SIG_free(sig);
	if (key) EC_KEY_free(key);

	FAILIF(!success, MR_E_INVALIDOP, "Failed to sign");
	return MR_E_SUCCESS;
}

mr_result ecc_getpublickey(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	FAILIF(!key || !publickey, MR_E_INVALIDARG, "!key || !publickey");
	FAILIF(!key->key, MR_E_INVALIDARG, "!key->key");
	FAILIF(publickeyspaceavail < 32, MR_E_INVALIDSIZE, "publickeyspaceavail < 32");

	BIGNUM* x = BN_new();
	BIGNUM* y = BN_new();

	EC_POINT* p = EC_KEY_get0_public_key(key->key);
	int success = x && y && p;

	if (success) success = EC_POINT_get_affine_coordinates(g_secp256r1, p, x, y, NULL);

	if (success) success = BN_bn2binpad(x, publickey + (32 - publickeyspaceavail), 32);

	if (x) BN_free(x);
	if (y) BN_free(y);

	FAILIF(!success, MR_E_INVALIDOP, "Could not get public key");
	return MR_E_SUCCESS;
}

mr_result ecc_getpublickey_point(const ecc_key* key, ecc_point* point)
{
	FAILIF(!key || !point, MR_E_INVALIDARG, "!key || !point");
	FAILIF(!key->key || !point->point, MR_E_INVALIDARG, "!key->key || !point->point");

	const EC_POINT* pub = EC_KEY_get0_public_key(key->key);
	FAILIF(!pub, MR_E_INVALIDOP, "Could not get public key");

	int success = EC_POINT_copy(point->point, pub);
	FAILIF(!success, MR_E_INVALIDOP, "Could not get public key");

	return MR_E_SUCCESS;
}

void ecc_free_point(ecc_point* point)
{
	if (point && point->point)
	{
		EC_POINT_free(point->point);
		point->point = 0;
	}
}

void ecc_free(ecc_key* key)
{
	if (key && key->key)
	{
		EC_KEY_free(key->key);
		key->key = 0;
	}
}