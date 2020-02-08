#include "pch.h"
#include "ecc_common.h"
#include <microratchet.h>



mr_result ecc_import_public(const uint8_t* otherpublickey, uint32_t otherpublickeysize, ecc_point *pub)
{
	return MR_E_NOTIMPL;
}


mr_result ecc_generate(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	return MR_E_SUCCESS;
}

uint32_t ecc_load(ecc_key* key, const uint8_t* data, uint32_t spaceavail)
{
	return 32;
}

mr_result ecc_store_size_needed(const mp_int* key)
{
	return 32;
}

mr_result ecc_store(const ecc_key* key, uint8_t* data, uint32_t spaceavail)
{
	return MR_E_NOTIMPL;
}

mr_result ecc_sign(const ecc_key *key, const uint8_t* digest, uint32_t digestsize, uint8_t* signature, uint32_t signaturespaceavail)
{
	return MR_E_NOTIMPL;
}

mr_result ecc_verify(const ecc_key *key, const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, uint32_t* result)
{
	return MR_E_NOTIMPL;
}

mr_result ecc_getpublickey(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	return MR_E_NOTIMPL;
}
