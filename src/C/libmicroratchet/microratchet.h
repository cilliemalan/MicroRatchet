#pragma once

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

	// error codes
#define E_SUCCESS 0
#define E_MORE 1
#define E_INVALIDARGUMENT -1
#define E_INVALIDSIZE -2
#define E_INVALIDOP -3
#define E_NOMEM -4
#define E_HARDWAREFAIL -5
#define E_VERIFYFAIL -6

	// these functions must be supplied by the integrating application.
	// The project will fail to link if they are not implemented.


	///// SHA 256
	
	mr_sha_ctx mr_sha_create(mr_ctx mr_ctx);
	int mr_sha_init(mr_sha_ctx ctx);
	int mr_sha_process(mr_sha_ctx ctx, const unsigned char* data, unsigned int howmuch);
	int mr_sha_compute(mr_sha_ctx ctx, unsigned char* output, unsigned int spaceavail);
	void mr_sha_destroy(mr_sha_ctx ctx);


	///// AES
	
	mr_aes_ctx mr_aes_create(mr_ctx mr_ctx);
	int mr_aes_init(mr_aes_ctx ctx, const unsigned char* key, unsigned int keysize);
	int mr_aes_process(mr_aes_ctx ctx, const unsigned char* data, unsigned int amount, unsigned char* output, unsigned int spaceavail);
	void mr_aes_destroy(mr_aes_ctx ctx);


	///// Poly1305 (with AES)

	mr_poly_ctx mr_poly_create(mr_ctx mr_ctx);
	int mr_poly_init(mr_poly_ctx ctx, const unsigned char* key, unsigned int keysize, const unsigned char* iv, unsigned int ivsize);
	int mr_poly_process(mr_poly_ctx ctx, const unsigned char* data, unsigned int amount);
	int mr_poly_compute(mr_poly_ctx ctx, unsigned char* output, unsigned int spaceavail);
	void mr_poly_destroy(mr_poly_ctx ctx);


	///// ECDH
	
	mr_ecdh_ctx mr_ecdh_create(mr_ctx mr_ctx);
	int mr_ecdh_generate(mr_ecdh_ctx ctx, unsigned char* publickey, unsigned int publickeyspaceavail, unsigned int* publickeysize);
	int mr_ecdh_load(mr_ecdh_ctx ctx, unsigned char* data, unsigned int spaceavail);
	int mr_ecdh_derivekey(mr_ecdh_ctx ctx, const unsigned char* otherpublickey, unsigned int otherpublickeysize, unsigned char* derivedkey, unsigned int derivedkeyspaceavail, unsigned int* derivedkeysize);
	int mr_ecdh_store_size_needed(mr_ecdh_ctx ctx);
	int mr_ecdh_store(mr_ecdh_ctx ctx, unsigned char* data, unsigned int spaceavail, unsigned int* amountstored);
	void mr_ecdh_destroy(mr_ecdh_ctx ctx);


	///// ECDSA
	
	mr_ecdsa_ctx mr_ecdsa_create(mr_ctx mr_ctx);
	int mr_ecdsa_generate(mr_ecdsa_ctx ctx, unsigned char* publickey, unsigned int publickeyspaceavail, unsigned int* publickeysize);
	int mr_ecdsa_load(mr_ecdsa_ctx ctx, unsigned char* data, unsigned int spaceavail, unsigned int* amountread);
	int mr_ecdsa_sign(mr_ecdsa_ctx ctx, const unsigned char* digest, unsigned int digestsize, unsigned char* signature, unsigned int signaturespaceavail, unsigned int* signaturesize);
	int mr_ecdsa_verify(mr_ecdsa_ctx _ctx, const unsigned char* signature, unsigned int signaturesize, const unsigned char* digest, unsigned int digestsize, unsigned int* result);
	int mr_ecdsa_store_size_needed(mr_ecdsa_ctx ctx);
	int mr_ecdsa_store(mr_ecdsa_ctx ctx, unsigned char* data, unsigned int spaceavail, unsigned int* amountstored);
	void mr_ecdsa_destroy(mr_ecdsa_ctx ctx);
	int mr_ecdsa_verify_other(const unsigned char* signature, unsigned int signaturesize, const unsigned char* digest, unsigned int digestsize, const unsigned char* publickey, unsigned int publickeysize, unsigned int* result, void* user);


	///// RNG
	
	mr_rng_ctx mr_rng_create(mr_ctx mr_ctx);
	int mr_rng_generate(mr_rng_ctx ctx, unsigned char* output, unsigned int outputsize);
	void mr_rng_destroy(mr_rng_ctx ctx);


	///// Storage

	// allocate some memory (i.e. malloc). Efforts must be made to ensure pointer is not deterministic.
	int mr_allocate(mr_ctx ctx, int amountrequested, void** pointer);

	// free some memory previously allocated with mr_allocate.
	void mr_free(mr_ctx ctx, void* pointer);


	///// communcation
	
	int mr_transmit(mr_ctx ctx, void* user, const unsigned char* data, int howmuch);



	// these functions and structures are the public interface for MicroRatchet

	// main configuration
	typedef struct t_mr_config {
		unsigned short mtu;
		unsigned char is_client;
	} mr_config;


	// implementation functions

	// create a new MicroRatchet client with the provided configuration. the client will hold a reference to the configuration.
	mr_ctx mrclient_create(mr_config* config);

	// process initialization. call this function when data received on the wire during the initialization phase.
	// Call with null for the first time to initiate initialization. This function will transmit data as needed by calling mr_transmit.
	// This function will return E_MORE when initialziation is not yet done. It will return E_SUCCESS when initialization has been completed.
	// If initialization has previously completed and the client is already initialized, this function will not attempt to communicate.
	// This function must be called with a complete message.
	int mrclient_process_initialization(mr_ctx ctx, const unsigned char* bytes, int numbytes);

	// process incoming data. Call this function when data is received on the wire after the client has been initialized.
	int mrclient_receive_data(mr_ctx ctx, const unsigned char* bytes, int numbytes, unsigned char** output, int spaceavail, int* outputspace);

	// transmit data. Call this function to send data after the client has been initialized.
	int mrclient_send_data(mr_ctx ctx, const unsigned char* data, int numbytes);

	// destroy a client
	void mrclient_destroy(mr_ctx ctx);


#ifdef __cplusplus
}
#endif