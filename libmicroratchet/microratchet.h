#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	// structures
	typedef void* sha_ctx;
	typedef void* aes_ctx;
	typedef void* gmac_ctx;
	typedef void* ecdh_ctx;
	typedef void* ecdsa_ctx;
	typedef void* rng_ctx;

	// error codes
#define E_SUCCESS 0
#define E_INVALIDARG -1
#define E_INVALIDSIZE -2
#define E_INVALIDOP -3
#define E_NOMEM -4

	// these functions must be supplied by the integrating application
	void* allocate(size_t howmuch);
	void deallocate(void* pointer);

	sha_ctx sha_create();
	int sha_init(sha_ctx ctx);
	int sha_process(sha_ctx ctx, const char* data, int howmuch);
	int sha_compute(sha_ctx ctx, char* output, int spaceavail);
	void sha_destroy(sha_ctx ctx);

	aes_ctx aes_create();
	int aes_init(aes_ctx ctx, const char* key, int keysize, const char* iv, int ivsize);
	int aes_process(aes_ctx ctx, const char* data, int amount, char* output, int spaceavail);
	void aes_destroy(aes_ctx ctx);

	gmac_ctx gmac_create();
	int gmac_init(gmac_ctx ctx, const char* key, int keysize, const char* iv, int ivsize);
	int gmac_process(gmac_ctx ctx, const char* data, int amount, char* output, int spaceavail);
	int gmac_compute(gmac_ctx ctx, char* output, int spaceavail);
	void gmac_destroy(gmac_ctx ctx);

	ecdh_ctx ecdh_create();
	int ecdh_generate(ecdh_ctx ctx, char* publickey, int publickeyspaceavail, int* publickeysize);
	int ecdh_load(ecdh_ctx ctx, char* data, int spaceavail, int* amountread);
	int ecdh_derivekey(ecdh_ctx ctx, const char* otherpublickey, int otherpublickeysize, char* derivedkey, int derivedkeyspaceavail, int* derivedkeysize);
	int ecdh_store_size_needed(ecdh_ctx ctx);
	int ecdh_store(ecdh_ctx ctx, char* data, int spaceavail, int* amountstored);
	void ecdh_destroy(gmac_ctx ctx);

	ecdsa_ctx ecdsa_create();
	int ecdsa_generate(ecdsa_ctx ctx, char* publickey, int publickeyspaceavail, int* publickeysize);
	int ecdsa_load(ecdsa_ctx ctx, char* data, int spaceavail, int* amountread);
	int ecdsa_sign(ecdsa_ctx ctx, const char* digest, int digestsize, char* signature, int signaturespaceavail, int* signaturesize);
	int ecdsa_verify(ecdsa_ctx ctx, const char* signature, int signaturesize);
	int ecdsa_store_size_needed(ecdsa_ctx ctx);
	int ecdsa_store(ecdsa_ctx ctx, char* data, int spaceavail, int* amountstored);
	void ecdsa_destroy(ecdsa_ctx ctx);
	int ecdsa_verify_other(const char* signature, int signaturesize, const char* digest, int digestsize, char* publickey, int publickeysize);

	rng_ctx rng_create();
	int rng_generate(rng_ctx ctx, char* output, int outputsize);
	void rng_destroy();

	int test();


#ifdef __cplusplus
}
#endif