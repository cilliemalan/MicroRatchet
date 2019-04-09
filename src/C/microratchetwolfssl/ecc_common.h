#pragma once

int ecc_import_public(const unsigned char* otherpublickey, unsigned int otherpublickeysize, ecc_point *pub);
int ecc_generate(ecc_key* key, unsigned char* publickey, unsigned int publickeyspaceavail);
int ecc_load(ecc_key* key, const unsigned char* data, unsigned int spaceavail);
int ecc_store_size_needed(const mp_int* key);
int ecc_store(const ecc_key* key, unsigned char* data, unsigned int spaceavail);
int ecc_sign(const ecc_key *key, const unsigned char* digest, unsigned int digestsize, unsigned char* signature, unsigned int signaturespaceavail);
int ecc_verify(const ecc_key *key, const unsigned char* signature, unsigned int signaturesize, const unsigned char* digest, unsigned int digestsize, unsigned int* result);