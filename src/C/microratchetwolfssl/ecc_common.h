#pragma once

int ecc_import_public(const uint8_t* otherpublickey, uint32_t otherpublickeysize, ecc_point *pub);
int ecc_generate(ecc_key* key, uint8_t* publickey, uint32_t publickeyspaceavail);
int ecc_load(ecc_key* key, const uint8_t* data, uint32_t spaceavail);
int ecc_store_size_needed(const mp_int* key);
int ecc_store(const ecc_key* key, uint8_t* data, uint32_t spaceavail);
int ecc_sign(const ecc_key *key, const uint8_t* digest, uint32_t digestsize, uint8_t* signature, uint32_t signaturespaceavail);
int ecc_verify(const ecc_key *key, const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, uint32_t* result);