#pragma once

int ecc_import_public(const unsigned char* otherpublickey, unsigned int otherpublickeysize, ecc_point *pub);
int ecc_generate(ecc_key* key, unsigned char* publickey, unsigned int publickeyspaceavail, unsigned int* publickeysize);
int ecc_load(ecc_key* key, unsigned char* data, unsigned int spaceavail);
int ecc_store_size_needed(const mp_int* key);
int ecc_store(const ecc_point* key, unsigned char* data, unsigned int spaceavail, unsigned int* amountstored);