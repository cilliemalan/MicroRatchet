#pragma once

#include <microratchet.h>
#include <mbedtls/ecp.h>

#ifdef __cplusplus
extern "C" {
#endif
	extern const mbedtls_ecp_curve_info* secp256r1_ci;
	extern mbedtls_ecp_group secp256r1_gp;

	typedef struct mbedtls_ecp_point ecc_point;
	typedef struct mbedtls_mpi mp_int;
	typedef struct { mp_int d; mbedtls_ecp_point Q; } ecc_key;

	mr_result ecc_import_public(const uint8_t* otherpublickey, uint32_t otherpublickeysize, ecc_point* pub);
	mr_result ecc_generate(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail, int (*f_rng)(void*, unsigned char*, size_t), void* p_rng);
	uint32_t ecc_load(ecc_key* key, const uint8_t* data, uint32_t spaceavail);
	mr_result ecc_store_size_needed(const ecc_key* key);
	mr_result ecc_store(const ecc_key* key, uint8_t* data, uint32_t spaceavail);
	mr_result ecc_sign(const ecc_key* key, const uint8_t* digest, uint32_t digestsize, uint8_t* signature, uint32_t signaturespaceavail, int (*f_rng)(void*, unsigned char*, size_t), void* p_rng);
	mr_result ecc_verify(const ecc_key* key, const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, uint32_t* result);
	mr_result ecc_getpublickey(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail);

#ifdef __cplusplus
}
#endif