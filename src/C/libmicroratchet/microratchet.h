#pragma once

#include <stdbool.h>
#include <stdint.h>

// structures
typedef void* mr_ctx;
typedef void* mr_sha_ctx;
typedef void* mr_aes_ctx;
typedef void* mr_poly_ctx;
typedef void* mr_ecdh_ctx;
typedef void* mr_ecdsa_ctx;
typedef void* mr_rng_ctx;

// main configuration
typedef struct t_mr_config {

	// true if this instance is a client. False if this instance is a server. The difference is that only a client can initiate a session.
	bool is_client;

	// the application key. Must match the key for the server.
	uint8_t applicationKey[32];
} mr_config;

// constants
typedef enum mr_result_e {
	MR_E_SUCCESS = 0,
	MR_E_SENDBACK = 1,
	MR_E_INVALIDARG = -1,
	MR_E_INVALIDSIZE = -2,
	MR_E_INVALIDOP = -3,
	MR_E_NOMEM = -4,
	MR_E_VERIFYFAIL = -5,
	MR_E_NOTFOUND = -6
} mr_result;

// the minimum amount of overhead. The message space
// available must be at least this much larger than
// the message payload.
#define MR_OVERHEAD_WITHOUT_ECDH 16

// the maximum amount of overhead. If the message
// space avaialble minus the payload size is larger
// than or equal to this, ECDH parameters will be
// included in the message.
#define MR_OVERHEAD_WITH_ECDH 48

// the minimum message size after encryption.
// when encrypting a message, at least this amount
// of space must be available.
#define MR_MIN_MESSAGE_SIZE 32

// the minimum message size after encryption when
// including ECDH parameters.
#define MR_MIN_MESSAGE_SIZE_WITH_ECDH 64

// the safe minimum message space needed for initialization
// messages. While initializing, provide messages at least
// this size. If at any point during the initialization
// process there is not enough space available, a function
// called will return MR_E_INVALIDSIZE.
#define MR_MAX_INITIALIZATION_MESSAGE_SIZE 256

// The size of an ECDSA or ECDH public key in bytes.
#define MR_PUBLIC_KEY_SIZE 32

#ifdef __cplusplus
	extern "C" {
#endif

	// portable functions

	// these functions must be supplied by the integrating application by
	// providing a custom implementation or by linking one of the supported
	// third-party integrated libraries (e.g. microratchetwolfssl)


	///// SHA 256

	mr_sha_ctx mr_sha_create(mr_ctx mr_ctx);
	mr_result mr_sha_init(mr_sha_ctx ctx);
	mr_result mr_sha_process(mr_sha_ctx ctx, const uint8_t* data, uint32_t howmuch);
	mr_result mr_sha_compute(mr_sha_ctx ctx, uint8_t* output, uint32_t spaceavail);
	void mr_sha_destroy(mr_sha_ctx ctx);


	///// AES

	mr_aes_ctx mr_aes_create(mr_ctx mr_ctx);
	mr_result mr_aes_init(mr_aes_ctx ctx, const uint8_t* key, uint32_t keysize);
	mr_result mr_aes_process(mr_aes_ctx ctx, const uint8_t* data, uint32_t amount, uint8_t* output, uint32_t spaceavail);
	void mr_aes_destroy(mr_aes_ctx ctx);


	///// Poly1305 (with AES)

	mr_poly_ctx mr_poly_create(mr_ctx mr_ctx);
	mr_result mr_poly_init(mr_poly_ctx ctx, const uint8_t* key, uint32_t keysize, const uint8_t* iv, uint32_t ivsize);
	mr_result mr_poly_process(mr_poly_ctx ctx, const uint8_t* data, uint32_t amount);
	mr_result mr_poly_compute(mr_poly_ctx ctx, uint8_t* output, uint32_t spaceavail);
	void mr_poly_destroy(mr_poly_ctx ctx);


	///// ECDH

	mr_ecdh_ctx mr_ecdh_create(mr_ctx mr_ctx);
	mr_result mr_ecdh_generate(mr_ecdh_ctx ctx, uint8_t* publickey, uint32_t publickeyspaceavail);
	uint32_t mr_ecdh_load(mr_ecdh_ctx ctx, const uint8_t* data, uint32_t spaceavail);
	mr_result mr_ecdh_derivekey(mr_ecdh_ctx ctx, const uint8_t* otherpublickey, uint32_t otherpublickeysize, uint8_t* derivedkey, uint32_t derivedkeyspaceavail);
	uint32_t mr_ecdh_store_size_needed(mr_ecdh_ctx ctx);
	mr_result mr_ecdh_store(mr_ecdh_ctx ctx, uint8_t* data, uint32_t spaceavail);
	mr_result mr_ecdh_setprivatekey(mr_ecdh_ctx ctx, const uint8_t* privatekey, uint32_t privatekeysize);
	mr_result mr_ecdh_getpublickey(mr_ecdh_ctx ctx, uint8_t* publickey, uint32_t publickeyspaceavail);
	void mr_ecdh_destroy(mr_ecdh_ctx ctx);


	///// ECDSA

	mr_ecdsa_ctx mr_ecdsa_create(mr_ctx mr_ctx);
	mr_result mr_ecdsa_setprivatekey(mr_ecdsa_ctx ctx, const uint8_t* privatekey, uint32_t privatekeysize);
	mr_result mr_ecdsa_getpublickey(mr_ecdsa_ctx ctx, uint8_t* publickey, uint32_t publickeyspaceavail);
	mr_result mr_ecdsa_generate(mr_ecdsa_ctx ctx, uint8_t* publickey, uint32_t publickeyspaceavail);
	uint32_t mr_ecdsa_load(mr_ecdsa_ctx ctx, const uint8_t* data, uint32_t spaceavail);
	mr_result mr_ecdsa_sign(mr_ecdsa_ctx ctx, const uint8_t* digest, uint32_t digestsize, uint8_t* signature, uint32_t signaturespaceavail);
	mr_result mr_ecdsa_verify(mr_ecdsa_ctx _ctx, const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, uint32_t* result);
	uint32_t mr_ecdsa_store_size_needed(mr_ecdsa_ctx ctx);
	mr_result mr_ecdsa_store(mr_ecdsa_ctx ctx, uint8_t* data, uint32_t spaceavail);
	void mr_ecdsa_destroy(mr_ecdsa_ctx ctx);
	mr_result mr_ecdsa_verify_other(const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, const uint8_t* publickey, uint32_t publickeysize, uint32_t* result);


	///// RNG

	mr_rng_ctx mr_rng_create(mr_ctx mr_ctx);
	mr_result mr_rng_generate(mr_rng_ctx ctx, uint8_t* output, uint32_t outputsize);
	void mr_rng_destroy(mr_rng_ctx ctx);


	///// Memory

	mr_result mr_allocate(mr_ctx ctx, int amountrequested, void** pointer);
	void mr_free(mr_ctx ctx, void* pointer);



	






	// implementation functions. Call these functions from your application.

	// create a new MicroRatchet context with the provided configuration. the client will hold a reference to the configuration.
	mr_ctx mr_ctx_create(const mr_config* config);

	// set the identity of a context. Must be done before initialization but need not be done
	// if initialization has already taken place. The identity ECDH object will not be freed
	// when the context is destroyed.
	mr_result mr_ctx_set_identity(mr_ctx ctx, mr_ecdsa_ctx identity);

	// initiate initialization. If the context is a client, this will create the first initialization message to
	// be sent to a server. The message will be created in message, which must provide at least
	// This call will fail if the context is already initialized. To force it to re-initialize, set the force argument to true.
	mr_result mr_ctx_initiate_initialization(mr_ctx ctx, uint8_t* message, uint32_t spaceavailable, bool force);

	// receive and decrypt data received from the other end. The message will be decrypted
	// in place and a pointer to the payload, as well as the payload size set. Note that
	// the payload size includes any padding that was added.
	// If a message is received which forms part of the initialization process, a response
	// will be provided in payload to be sent back. In this case the return code will be
	// MR_E_SENDBACK. Once initialization is complete, mr_ctx_receive will return E_SUCCESS with
	// no payload.
	mr_result mr_ctx_receive(mr_ctx ctx, uint8_t* message, uint32_t messagesize, uint32_t spaceavailable, uint8_t** payload, uint32_t* paylodsize);

	// encrypt a payload for sending. The payload will be encrypted in place to fill up to messagesize.
	// messagesize must be at least MR_OVERHEAD_WITHOUT_ECDH bytes larger than payloadsize and be at least
	// MR_MIN_MESSAGE_SIZE. If the message size is MR_OVERHEAD_WITH_ECDH bytes larger than the payload and
	// at least 64 bytes total, ECDH parameters for key exchange will be included.
	mr_result mr_ctx_send(mr_ctx ctx, uint8_t* payload, uint32_t payloadsize, uint32_t messagesize);

	// reports the amount of space needed to store the context.
	uint32_t mr_ctx_state_size_needed(mr_ctx ctx);

	// stores the state for later loading in a memory buffer.
	mr_result mr_ctx_state_store(mr_ctx ctx, uint8_t* destination, uint32_t spaceavailable);

	// loads state for a context from a memory buffer.
	mr_result mr_ctx_state_load(mr_ctx ctx, const uint8_t* data, uint32_t amount, uint32_t* amountread);

	// destroys a context and frees all related memory. The identity ECDH object
	// will not be destroyed.
	void mr_ctx_destroy(mr_ctx ctx);


#ifdef __cplusplus
}
#endif