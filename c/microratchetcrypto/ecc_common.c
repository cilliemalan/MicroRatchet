#include "pch.h"
#include <microratchet.h>
#include "ecc_common.h"

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

	return MR_E_NOTIMPL;
}

mr_result ecc_generate(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	FAILIF(!key, MR_E_INVALIDARG, "!key");
	FAILIF(publickey && publickeyspaceavail < 32, MR_E_INVALIDSIZE, "Need 32 bytes for public key");

	return MR_E_NOTIMPL;
}

uint32_t ecc_load(ecc_key* key, const uint8_t* data, uint32_t size)
{
	FAILIF(!key, MR_E_INVALIDARG, "!key");
	FAILIF(!data, MR_E_INVALIDARG, "!data");
	FAILIF(size < 32, MR_E_INVALIDARG, "size must be at least 32 bytes");

	memcpy(key->d, data, 32);

	return MR_E_SUCCESS;
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

	return MR_E_NOTIMPL;
}

mr_result ecc_verify(const ecc_point* pub, const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, uint32_t* result)
{
	FAILIF(!pub || !digest || !signature || !signaturesize, MR_E_INVALIDARG, "!key || !digest || !signature || !signaturesize");
	FAILIF(signaturesize != 64, MR_E_INVALIDSIZE, "signaturesize != 64");
	FAILIF(digestsize != 32, MR_E_INVALIDSIZE, "digestsize != 32");

	return MR_E_NOTIMPL;
}

mr_result ecc_verify_other(const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, const uint8_t* publickey, uint32_t publickeysize, uint32_t* result)
{
	FAILIF(!publickey || !digest || !signature || !signaturesize, MR_E_INVALIDARG, "!publickey || !digest || !signature || !signaturesize");
	FAILIF(signaturesize != 64, MR_E_INVALIDSIZE, "signaturesize != 64");
	FAILIF(digestsize != 32, MR_E_INVALIDSIZE, "digestsize != 32");
	FAILIF(publickeysize != 32, MR_E_INVALIDSIZE, "publickeysize != 32");

	return MR_E_NOTIMPL;
}

mr_result ecc_derivekey(const ecc_key* key, const uint8_t* otherpublickey, uint32_t otherpublickeysize, uint8_t* derivedkey, uint32_t derivedkeyspaceavail)
{
	FAILIF(!key || !otherpublickey || !derivedkey, MR_E_INVALIDARG, "!key || !otherpublickey || !derivedkey");
	FAILIF(otherpublickeysize != 64, MR_E_INVALIDSIZE, "otherpublickeysize != 64");
	FAILIF(derivedkeyspaceavail < 32, MR_E_INVALIDSIZE, "derivedkeyspaceavail < 32");

	return MR_E_NOTIMPL;
}

mr_result ecc_getpublickey(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	FAILIF(!key || !publickey, MR_E_INVALIDARG, "!key || !publickey");
	FAILIF(publickeyspaceavail < 32, MR_E_INVALIDSIZE, "publickeyspaceavail < 32");

	return MR_E_NOTIMPL;
}

mr_result ecc_getpublickey_point(const ecc_key* key, ecc_point* point)
{
	FAILIF(!key || !point, MR_E_INVALIDARG, "!key || !point");

	return MR_E_NOTIMPL;
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
