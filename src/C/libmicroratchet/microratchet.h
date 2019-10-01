#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	// structures
	typedef void* mr_ctx;
	typedef void* mr_sha_ctx;
	typedef void* mr_aes_ctx;
	typedef void* mr_poly_ctx;
	typedef void* mr_ecdh_ctx;
	typedef void* mr_ecdsa_ctx;
	typedef void* mr_rng_ctx;

	typedef enum mr_result_e {
		E_SUCCESS = 0,
		E_MORE = 1,
		E_INVALIDARGUMENT = -1,
		E_INVALIDSIZE = -2,
		E_INVALIDOP = -3,
		E_NOMEM = -4,
		E_HARDWAREFAIL = -5,
		E_VERIFYFAIL = -6,
		E_KEYLOST = -7,
		E_NOTFOUND = -7
	} mr_result_t;

	// these functions must be supplied by the integrating application.
	// The project will fail to link if they are not implemented.


	///// SHA 256

	mr_sha_ctx mr_sha_create(mr_ctx mr_ctx);
	mr_result_t mr_sha_init(mr_sha_ctx ctx);
	mr_result_t mr_sha_process(mr_sha_ctx ctx, const uint8_t* data, uint32_t howmuch);
	mr_result_t mr_sha_compute(mr_sha_ctx ctx, uint8_t* output, uint32_t spaceavail);
	void mr_sha_destroy(mr_sha_ctx ctx);


	///// AES

	mr_aes_ctx mr_aes_create(mr_ctx mr_ctx);
	mr_result_t mr_aes_init(mr_aes_ctx ctx, const uint8_t* key, uint32_t keysize);
	mr_result_t mr_aes_process(mr_aes_ctx ctx, const uint8_t* data, uint32_t amount, uint8_t* output, uint32_t spaceavail);
	void mr_aes_destroy(mr_aes_ctx ctx);


	///// Poly1305 (with AES)

	mr_poly_ctx mr_poly_create(mr_ctx mr_ctx);
	mr_result_t mr_poly_init(mr_poly_ctx ctx, const uint8_t* key, uint32_t keysize, const uint8_t* iv, uint32_t ivsize);
	mr_result_t mr_poly_process(mr_poly_ctx ctx, const uint8_t* data, uint32_t amount);
	mr_result_t mr_poly_compute(mr_poly_ctx ctx, uint8_t* output, uint32_t spaceavail);
	void mr_poly_destroy(mr_poly_ctx ctx);


	///// ECDH

	mr_ecdh_ctx mr_ecdh_create(mr_ctx mr_ctx);
	mr_result_t mr_ecdh_generate(mr_ecdh_ctx ctx, uint8_t* publickey, uint32_t publickeyspaceavail);
	mr_result_t mr_ecdh_load(mr_ecdh_ctx ctx, uint8_t* data, uint32_t spaceavail);
	mr_result_t mr_ecdh_derivekey(mr_ecdh_ctx ctx, const uint8_t* otherpublickey, uint32_t otherpublickeysize, uint8_t* derivedkey, uint32_t derivedkeyspaceavail);
	uint32_t mr_ecdh_store_size_needed(mr_ecdh_ctx ctx);
	mr_result_t mr_ecdh_store(mr_ecdh_ctx ctx, uint8_t* data, uint32_t spaceavail);
	mr_result_t mr_ecdh_setprivatekey(mr_ecdh_ctx ctx, const uint8_t* privatekey, uint32_t privatekeysize);
	mr_result_t mr_ecdh_getpublickey(mr_ecdh_ctx ctx, uint8_t* publickey, uint32_t publickeyspaceavail);
	void mr_ecdh_destroy(mr_ecdh_ctx ctx);


	///// ECDSA

	mr_ecdsa_ctx mr_ecdsa_create(mr_ctx mr_ctx);
	mr_result_t mr_ecdsa_setprivatekey(mr_ecdsa_ctx ctx, const uint8_t* privatekey, uint32_t privatekeysize);
	mr_result_t mr_ecdsa_getpublickey(mr_ecdsa_ctx ctx, uint8_t* publickey, uint32_t publickeyspaceavail);
	mr_result_t mr_ecdsa_generate(mr_ecdsa_ctx ctx, uint8_t* publickey, uint32_t publickeyspaceavail);
	mr_result_t mr_ecdsa_load(mr_ecdsa_ctx ctx, uint8_t* data, uint32_t spaceavail);
	mr_result_t mr_ecdsa_sign(mr_ecdsa_ctx ctx, const uint8_t* digest, uint32_t digestsize, uint8_t* signature, uint32_t signaturespaceavail);
	mr_result_t mr_ecdsa_verify(mr_ecdsa_ctx _ctx, const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, uint32_t* result);
	mr_result_t mr_ecdsa_store_size_needed(mr_ecdsa_ctx ctx);
	mr_result_t mr_ecdsa_store(mr_ecdsa_ctx ctx, uint8_t* data, uint32_t spaceavail);
	void mr_ecdsa_destroy(mr_ecdsa_ctx ctx);
	mr_result_t mr_ecdsa_verify_other(const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, const uint8_t* publickey, uint32_t publickeysize, uint32_t* result);


	///// RNG

	mr_rng_ctx mr_rng_create(mr_ctx mr_ctx);
	mr_result_t mr_rng_generate(mr_rng_ctx ctx, uint8_t* output, uint32_t outputsize);
	void mr_rng_destroy(mr_rng_ctx ctx);


	///// Storage

	// allocate some memory (i.e. malloc).
	mr_result_t mr_allocate(mr_ctx ctx, int amountrequested, void** pointer);

	// free some memory previously allocated with mr_allocate.
	void mr_free(mr_ctx ctx, void* pointer);



	// these functions and structures are the public interface for MicroRatchet

	// main configuration
	typedef struct t_mr_config {
		uint32_t minimum_message_size;
		uint32_t maximum_message_size;
		bool is_client;
	} mr_config;


	// implementation functions

	// create a new MicroRatchet client with the provided configuration. the client will hold a reference to the configuration.
	mr_ctx mrclient_create(mr_config* config);
	int mrclient_initiate_initialization(mr_ctx ctx, int force);
	int mrclient_receive_data(mr_ctx ctx, const uint8_t* data, uint32_t datasize, uint8_t* output, uint32_t spaceAvail);
	int mrclient_send_data(mr_ctx ctx, const uint8_t* data, uint32_t datasize, int mustPad);
	void mrclient_destroy(mr_ctx ctx);


#ifdef __cplusplus
}
#endif