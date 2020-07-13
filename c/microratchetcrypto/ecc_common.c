#include "pch.h"
#include <microratchet.h>
#include "ecc_common.h"

secp256k1_context* psecp256ctx = 0;
static void* psecp256mem = 0;

static int nophashfun(unsigned char* output, const unsigned char* x32, const unsigned char* y32, void* data)
{
	if (x32 != output)
	{
		memcpy(output, x32, 32);
	}
	return 1;
}

static int noncefun(
	unsigned char* nonce32,
	const unsigned char* msg32,
	const unsigned char* key32,
	const unsigned char* algo16,
	void* data,
	unsigned int attempt
)
{
	return !mr_rng_generate(0, nonce32, 32);
}

void errorcallback(const char* message, void* data)
{
	MR_WRITE(message, strlen(message));
	MR_ABORT();
}

mr_result ecc_initialize(mr_ctx ctx)
{
	if (!psecp256ctx)
	{
		uint32_t secp256flags = SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN;
		_C(mr_allocate(ctx, secp256k1_context_preallocated_size(secp256flags), &psecp256mem));

		psecp256ctx = secp256k1_context_preallocated_create(
			psecp256mem,
			secp256flags);

		if (!psecp256ctx)
		{
			return MR_E_NOMEM;
		}

		// void (*fun)(const char* message, void* data)
		secp256k1_context_set_illegal_callback(psecp256ctx, errorcallback, 0);
		secp256k1_context_set_error_callback(psecp256ctx, errorcallback, 0);
	}

	return MR_E_SUCCESS;
}

mr_result ecc_new(ecc_key* key)
{
	FAILIF(!key, MR_E_INVALIDARG, "key cannot be null");
	memset(key, 0, sizeof(ecc_key));

	return MR_E_SUCCESS;
}

mr_result ecc_new_point(ecc_point* point)
{
	FAILIF(!point, MR_E_INVALIDARG, "point cannot be null");
	memset(point, 0, sizeof(ecc_point));

	return MR_E_SUCCESS;
}

mr_result ecc_import_public(const uint8_t* otherpublickey, uint32_t otherpublickeysize, ecc_point* pub)
{
	FAILIF(!otherpublickey, MR_E_INVALIDARG, "!otherpublickey");
	FAILIF(!pub, MR_E_INVALIDARG, "!pub");
	FAILIF(otherpublickeysize != 32, MR_E_INVALIDSIZE, "other public key must be 32 bytes");
	FAILIF(!psecp256ctx, MR_E_INVALIDOP, "ecc_initialize was not called first");

	int r = secp256k1_ec_pubkey_parse(psecp256ctx, &pub->pubkey, otherpublickey, 32);
	FAILIF(!r, MR_E_INVALIDOP, "Could not read signature");

	return MR_E_SUCCESS;
}

mr_result ecc_generate(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	FAILIF(!key, MR_E_INVALIDARG, "!key");
	FAILIF(publickey && publickeyspaceavail < 32, MR_E_INVALIDSIZE, "Need 32 bytes for public key");
	FAILIF(!psecp256ctx, MR_E_INVALIDOP, "ecc_initialize was not called first");

	// used as a dummy when publickey is not specified
	static uint8_t tmppub[32];

	if (publickeyspaceavail > 32)
	{
		publickeyspaceavail = 32;
	}

	if (!publickey)
	{
		publickey = tmppub;
		publickeyspaceavail = 32;
	}

	uint32_t* privatekey = (uint32_t*)key->d;
	secp256k1_pubkey pub;
	for (uint32_t i = 0;; i++)
	{
		_C(mr_rng_generate(0, (uint8_t*)privatekey, 32));

		// one in a jillion bazillion or RNG broken
		if (i == 60)
		{
			return MR_E_RNGFAIL;
		}

		// quite impossible but we must check
		if ((privatekey[0] == 0xffffffff && privatekey[1] == 0xffffffff) ||
			(privatekey[0] == 0 && privatekey[1] == 0))
		{
			continue;
		}

		// this will fail if the private key is invalid. The above line
		// should ensure it's always valid
		if (!secp256k1_ec_pubkey_create(psecp256ctx, &pub, key->d))
		{
			continue;
		}

		// when publickeyspaceavail == 32, this will only succeed if the
		// public key Y coordinate is even.
		size_t outputlen = publickeyspaceavail;
		if (secp256k1_ec_pubkey_serialize(psecp256ctx, 
			publickey, 
			&outputlen,
			&pub, 
			SECP256K1_EC_COMPRESSED))
		{
			if (secp256k1_ec_pubkey_parse(psecp256ctx, &pub, publickey, 32))
			{
				break;
			}
			else
			{
				// TODO: weird?
			}
		}
	}

	return MR_E_SUCCESS;
}

uint32_t ecc_load(ecc_key* key, const uint8_t* data, uint32_t size)
{
	FAILIF(!key, MR_E_INVALIDARG, "!key");
	FAILIF(!data, MR_E_INVALIDARG, "!data");
	FAILIF(size < 32, MR_E_INVALIDARG, "size must be at least 32 bytes");

	memcpy(key->d, data, 32);

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

	memcpy(data, key->d, 32);

	return MR_E_SUCCESS;
}

mr_result ecc_sign(const ecc_key* key, const uint8_t* digest, uint32_t digestsize, uint8_t* signature, uint32_t signaturespaceavail)
{
	FAILIF(!key || !digest || !signature, MR_E_INVALIDARG, "!key || !digest || !signature");
	FAILIF(signaturespaceavail < 64, MR_E_INVALIDSIZE, "signaturespaceavail < 64");
	FAILIF(!psecp256ctx, MR_E_INVALIDOP, "ecc_initialize was not called first");

	secp256k1_ecdsa_signature sig;
	int r = secp256k1_ecdsa_sign(psecp256ctx, &sig, digest, key->d, noncefun, 0);
	FAILIF(!r, MR_E_INVALIDOP, "Could not sign the message");
	r = secp256k1_ecdsa_signature_serialize_compact(psecp256ctx, signature, &sig);
	FAILIF(!r, MR_E_INVALIDOP, "Could not store the signature");

	return MR_E_SUCCESS;
}

mr_result ecc_verify(const ecc_point* pub, const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, uint32_t* result)
{
	FAILIF(!pub || !digest || !signature || !signaturesize, MR_E_INVALIDARG, "!key || !digest || !signature || !signaturesize");
	FAILIF(signaturesize != 64, MR_E_INVALIDSIZE, "signaturesize != 64");
	FAILIF(digestsize != 32, MR_E_INVALIDSIZE, "digestsize != 32");
	FAILIF(!psecp256ctx, MR_E_INVALIDOP, "ecc_initialize was not called first");

	secp256k1_ecdsa_signature sig;
	bool r = secp256k1_ecdsa_signature_parse_compact(psecp256ctx, &sig, signature);
	FAILIF(!r, MR_E_INVALIDOP, "Failed to parse signature");

	r = secp256k1_ecdsa_verify(psecp256ctx, &sig, digest, &pub->pubkey);
	if (result)
	{
		*result = r;
	}

	return MR_E_SUCCESS;
}

mr_result ecc_verify_other(const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, const uint8_t* publickey, uint32_t publickeysize, uint32_t* result)
{
	FAILIF(!publickey || !digest || !signature || !signaturesize, MR_E_INVALIDARG, "!publickey || !digest || !signature || !signaturesize");
	FAILIF(signaturesize != 64, MR_E_INVALIDSIZE, "signaturesize != 64");
	FAILIF(digestsize != 32, MR_E_INVALIDSIZE, "digestsize != 32");
	FAILIF(publickeysize != 32, MR_E_INVALIDSIZE, "publickeysize != 32");

	ecc_point pnt;
	_C(ecc_import_public(publickey, publickeysize, &pnt));
	_C(ecc_verify(&pnt, signature, signaturesize, digest, digestsize, result));
	return MR_E_SUCCESS;
}

mr_result ecc_derivekey(const ecc_key* key, const uint8_t* otherpublickey, uint32_t otherpublickeysize, uint8_t* derivedkey, uint32_t derivedkeyspaceavail)
{
	FAILIF(!key || !otherpublickey || !derivedkey, MR_E_INVALIDARG, "!key || !otherpublickey || !derivedkey");
	FAILIF(otherpublickeysize != 32, MR_E_INVALIDSIZE, "otherpublickeysize != 32");
	FAILIF(derivedkeyspaceavail < 32, MR_E_INVALIDSIZE, "derivedkeyspaceavail < 32");
	FAILIF(!psecp256ctx, MR_E_INVALIDOP, "ecc_initialize was not called first");

	secp256k1_pubkey pub;
	bool r = secp256k1_ec_pubkey_parse(psecp256ctx, &pub, otherpublickey, 32);
	FAILIF(!r, MR_E_INVALIDOP, "Failed to parse public key");

	r = secp256k1_ecdh(psecp256ctx, derivedkey, &pub, key->d, nophashfun, 0);
	FAILIF(!r, MR_E_INVALIDOP, "Failed to compute shared secret");

	return MR_E_SUCCESS;
}

mr_result ecc_getpublickey(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	FAILIF(!key || !publickey, MR_E_INVALIDARG, "!key || !publickey");
	FAILIF(publickeyspaceavail < 32, MR_E_INVALIDSIZE, "publickeyspaceavail < 32");
	FAILIF(!psecp256ctx, MR_E_INVALIDOP, "ecc_initialize was not called first");
	publickeyspaceavail = 32;

	ecc_point p;
	_C(ecc_getpublickey_point(key, &p));
	size_t outputsize = publickeyspaceavail;
	int r = secp256k1_ec_pubkey_serialize(psecp256ctx, 
		publickey, 
		&outputsize,
		&p.pubkey, 
		SECP256K1_EC_COMPRESSED);
	FAILIF(!r, MR_E_INVALIDOP, "Could not serialize public key");

	return MR_E_SUCCESS;
}

mr_result ecc_getpublickey_point(const ecc_key* key, ecc_point* point)
{
	FAILIF(!key || !point, MR_E_INVALIDARG, "!key || !point");
	FAILIF(!psecp256ctx, MR_E_INVALIDOP, "ecc_initialize was not called first");

	int r = secp256k1_ec_pubkey_create(psecp256ctx, &point->pubkey, key->d);
	FAILIF(!r, MR_E_INVALIDOP, "Failed to get public key from private key");

	return MR_E_SUCCESS;
}

void ecc_free_point(ecc_point* point)
{
	if (point)
	{
		memset(point, 0, sizeof(ecc_point));
	}
}

void ecc_free(ecc_key* key)
{
	if (key)
	{
		memset(key, 0, sizeof(ecc_key));
	}
}
