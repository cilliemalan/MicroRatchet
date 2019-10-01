#pragma once

mr_result_t ecc_import_public(const uint8_t* otherpublickey, uint32_t otherpublickeysize, ecc_point *pub);
mr_result_t ecc_generate(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail);
mr_result_t ecc_load(ecc_key* key, const uint8_t* data, uint32_t spaceavail);
mr_result_t ecc_store_size_needed(const mp_int* key);
mr_result_t ecc_store(const ecc_key* key, uint8_t* data, uint32_t spaceavail);
mr_result_t ecc_sign(const ecc_key *key, const uint8_t* digest, uint32_t digestsize, uint8_t* signature, uint32_t signaturespaceavail);
mr_result_t ecc_verify(const ecc_key *key, const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, uint32_t* result);
