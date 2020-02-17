#include "pch.h"
#include <microratchet.h>
#include "ecc_common.h"

mr_result ecc_import_public(const uint8_t* otherpublickey, uint32_t otherpublickeysize, ecc_point *pub)
{
	return MR_E_NOTIMPL;
}


mr_result ecc_generate(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	FAILIF(!key, MR_E_INVALIDARG, "!key")

	return MR_E_NOTIMPL;
}

uint32_t ecc_load(ecc_key* key, const uint8_t* data, uint32_t spaceavail)
{
	*key = (ecc_key){ 0 };

	return 99999;
}

mr_result ecc_store_size_needed(const ecc_key* key)
{
	return 32;
}

mr_result ecc_store(const ecc_key* key, uint8_t* data, uint32_t spaceavail)
{
	FAILIF(!key || !data, MR_E_INVALIDARG, "!key || !data");
	FAILIF(spaceavail < 32, MR_E_INVALIDSIZE, "spaceavail < 32");

	return MR_E_NOTIMPL;
}

mr_result ecc_sign(const ecc_key *key, const uint8_t* digest, uint32_t digestsize, uint8_t* signature, uint32_t signaturespaceavail)
{
	FAILIF(!key || !digest || !signature, MR_E_INVALIDARG, "!key || !digest || !signature")
	FAILIF(signaturespaceavail < 64, MR_E_INVALIDSIZE, "signaturespaceavail < 64")

	return MR_E_NOTIMPL;
}

mr_result ecc_verify(const ecc_key *key, const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, uint32_t* result)
{
	FAILIF(!key || !digest || !signature || !signaturesize, MR_E_INVALIDARG, "!key || !digest || !signature || !signaturesize")
	FAILIF(signaturesize != 64, MR_E_INVALIDSIZE, "signaturesize != 64")

	return MR_E_NOTIMPL;
}

mr_result ecc_getpublickey(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	FAILIF(!key || !publickey, MR_E_INVALIDARG, "!key || !publickey")
	FAILIF(publickeyspaceavail < 32, MR_E_INVALIDSIZE, "publickeyspaceavail < 32")
	
	return MR_E_NOTIMPL;
}
