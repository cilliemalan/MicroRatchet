#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HEADER_EC_H
	typedef struct ec_point_st EC_POINT;
	typedef struct ec_key_st EC_KEY;
#endif

	typedef struct ecc_point
	{
		EC_POINT* point;
	} ecc_point;

	typedef struct ecc_key
	{
		EC_KEY* key;
	} ecc_key;

	static inline mr_result ecc_initialize(mr_ctx ctx) { return MR_E_SUCCESS; }
	mr_result ecc_new(ecc_key* key);
	mr_result ecc_new_point(ecc_point* point);
	mr_result ecc_import_public(const uint8_t* otherpublickey, uint32_t otherpublickeysize, ecc_point* pub);
	mr_result ecc_generate(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail);
	uint32_t ecc_load(ecc_key* key, const uint8_t* data, uint32_t spaceavail);
	mr_result ecc_store_size_needed(const ecc_key* key);
	mr_result ecc_store(const ecc_key* key, uint8_t* data, uint32_t spaceavail);
	mr_result ecc_sign(const ecc_key* key, const uint8_t* digest, uint32_t digestsize, uint8_t* signature, uint32_t signaturespaceavail);
	mr_result ecc_verify(const ecc_point* pub, const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, uint32_t* result);
	mr_result ecc_verify_other(const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, const uint8_t* publickey, uint32_t publickeysize, uint32_t* result);
	mr_result ecc_derivekey(const ecc_key* key, const uint8_t* otherpublickey, uint32_t otherpublickeysize, uint8_t* derivedkey, uint32_t derivedkeyspaceavail);
	mr_result ecc_getpublickey(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail);
	mr_result ecc_getpublickey_point(const ecc_key* key, ecc_point* pnt);
	void ecc_free_point(ecc_point* point);
	void ecc_free(ecc_key* key);

#ifdef __cplusplus
}
#endif