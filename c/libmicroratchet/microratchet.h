#pragma once

#include <stdbool.h>
#include <stdint.h>

// includes a specified file if desired. Use this by
// adding, for example
// -DMR_CONFIG=<myconfig.h> -Imyconfiglocation
// to your compiler command line or cmake or whatever
// an example config file is given in config.example.h
#ifdef MR_CONFIG
#include MR_CONFIG
#endif

// structures
typedef void* mr_ctx;
typedef void* mr_sha_ctx;
typedef void* mr_aes_ctx;
typedef void* mr_poly_ctx;
typedef void* mr_ecdh_ctx;
typedef void* mr_ecdsa_ctx;
typedef void* mr_rng_ctx;

// high-level callback definitions
typedef void (*data_callback_fn)(void* user, const uint8_t* data, uint32_t amount);
typedef uint32_t(*transmit_fn)(void* user, const uint8_t* data, uint32_t amount);
typedef uint32_t(*receive_fn)(void* user, uint8_t* data, uint32_t amount);
typedef void* (*waithandle_fn)(void* user);
typedef void (*waithandledestroy_fn)(void* user, void* waithandle);
typedef bool (*wait_fn)(void* user, void* handle, uint32_t timeout);
typedef void (*notify_fn)(void* user, void* handle);
typedef bool (*checkkey_fn)(void* user, const uint8_t* pubkey, uint32_t len);

// main configuration
typedef struct t_mr_config {

	// true if this instance is a client. False if this instance is a server. The difference is that only a client can initiate a session.
	bool is_client;

	// the application key. Must match the key for the server.
	uint8_t applicationKey[32];
} mr_config;

// high-level configuration
typedef struct t_mr_hlconfig {
	// user defined data used in callbacks.
	void* user;

	// create a wait handle to be waited upon by wait and notified by notify.
	// This can, for example, create a ciritcal section in windows, a mutex
	// or semaphore on another operating system, or just return the thread ID
	// for something like RTOS where threads can be unblocked directly.
	waithandle_fn create_wait_handle;

	// destroy a waut handle created with create_wait_handle.
	waithandledestroy_fn destroy_wait_handle;

	// wait for notification function. When this function is called it should
	// block until notify is called. It should also free the wait handle upon
	// return. The return value should indicate whether a notification was 
	// received.
	wait_fn wait;

	// notify function. When this function is called the wait function above should
	// unblock. Also call this function when data is received.
	notify_fn notify;

	// transmit function called by the main loop to transmit data.
	transmit_fn transmit;

	// receive function called by the main loop to receive data. This is called
	// by the main loop process when mr_hl_receive is called.
	receive_fn receive;

	// data callback function called when a mesage has been received.
	data_callback_fn data_callback;

	// check key callback called when establishing session to verify
	// trust for the remote public key.
	checkkey_fn checkkey_callback;

	// the amount which to round up message sizes. Set to 1 to always send
	// the exact amount. Set to a larger number (e.g. 16) to pad messages
	// to a multiple of that.
	uint32_t message_quantization;

	// how often to send new ECDH paramters. if 0 or 1, ECDH parameters will
	// be sent every message.
	uint32_t ecdh_frequency;
} mr_hl_config;

// The result of an operation. Note: when an error is returned and MR_DEBUG
// is set, MR_WRITE will be called with the reason for the failure.
typedef enum mr_result_e {
	// everything is fine.
	MR_E_SUCCESS = 0,
	// if returned by mr_ctx_receive, you need to send
	// data back over the wire. The data to send will
	// be in the payload and payloadsize arguments.
	MR_E_SENDBACK = 1,
	// returned when a high-level function is called with
	// a timeout of zero. Indicates that the requested action
	// was enqueued but does not indicate whether or not the
	// action succeeded.
	MR_E_ACTION_ENQUEUED = 2,
	// one of the arguments passed was invalid.
	MR_E_INVALIDARG = -1,
	// one of the sizes passed was invalid or too small.
	MR_E_INVALIDSIZE = -2,
	// the system is not in the valid state for this operation.
	MR_E_INVALIDOP = -3,
	// an allocation failed.
	MR_E_NOMEM = -4,
	// signature verification failed.
	MR_E_VERIFYFAIL = -5,
	// something was not found (i.e. a ratchet or chain key).
	MR_E_NOTFOUND = -6,
	// generating a random number failed.
	MR_E_RNGFAIL = -7,
	// the function is not implemented.
	MR_E_NOTIMPL = -8,
	// a call to an external library function failed (i.e. a call to wolfssl or openssl failed).
	MR_E_FAIL = -9,
	// a high-level function has timed out.
	MR_E_TIMEOUT = -10
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
// messages. While initializing, provide messages of
// this size. If at any point during the initialization
// process there is not enough space available, a function
// called will return MR_E_INVALIDSIZE.
#define MR_MAX_INITIALIZATION_MESSAGE_SIZE 256

// The size of an ECDSA or ECDH public key in bytes.
#define MR_PUBLIC_KEY_SIZE 32

#ifdef __cplusplus
extern "C" {
#endif

	// crypto functions

	// these functions must be supplied by the integrating application by
	// providing a custom implementation or by linking one of the supported
	// third-party integrated libraries (e.g. microratchetwolfssl)



	///// SHA 256
	// For computation of message digests and transforming ECDH keys.

	// allocate a new SHA256 context.
	mr_sha_ctx mr_sha_create(mr_ctx mr_ctx);
	// initialize or reset a SHA256  context.
	mr_result mr_sha_init(mr_sha_ctx ctx);
	// ingest data for SHA256 computation.
	mr_result mr_sha_process(mr_sha_ctx ctx, const uint8_t* data, uint32_t howmuch);
	// compute the SHA256 hash based on data ingested.
	mr_result mr_sha_compute(mr_sha_ctx ctx, uint8_t* output, uint32_t spaceavail);
	// free a SHA256 context.
	void mr_sha_destroy(mr_sha_ctx ctx);



	///// AES
	// for the encryption of messages and transforming of keys. Only the straight
	// one block encryption operation is required (i.e. ECB and no decryption). 
	// No cipher chaining operations are required as microratchet has its own 
	// CTR implementation.

	// allocate a new AES context.
	mr_aes_ctx mr_aes_create(mr_ctx mr_ctx);
	// initialize an AES context with a given key. keysize will be 16 or 32.
	mr_result mr_aes_init(mr_aes_ctx ctx, const uint8_t* key, uint32_t keysize);
	// encrypt one AES block. amount will be 16.
	mr_result mr_aes_process(mr_aes_ctx ctx, const uint8_t* data, uint32_t amount, uint8_t* output, uint32_t spaceavail);
	// free an AES context.
	void mr_aes_destroy(mr_aes_ctx ctx);



	///// Poly1305 (with AES)
	// For the computation of message authentication codes. A Poly1305-AES implementation based
	// on the original paper is required where part of the key is derived by processing with AES.
	// (many modern implementations are either PolyChaCha or non-AES Poly1305)

	// allocate a new Poly1305AES context.
	mr_poly_ctx mr_poly_create(mr_ctx mr_ctx);
	// initialize a Poly1305AES context with a given key and IV. keysize will be 32 and ivsize will be 16.
	mr_result mr_poly_init(mr_poly_ctx ctx, const uint8_t* key, uint32_t keysize, const uint8_t* iv, uint32_t ivsize);
	// process data for mr_poly_init computation.
	mr_result mr_poly_process(mr_poly_ctx ctx, const uint8_t* data, uint32_t amount);
	// compute a Poly1305AES MAC. truncate the MAC if it is larger than spaceavail. spaceavail will not be smaller than 12 bytes.
	mr_result mr_poly_compute(mr_poly_ctx ctx, uint8_t* output, uint32_t spaceavail);
	// free a Poly1305AES context.
	void mr_poly_destroy(mr_poly_ctx ctx);


	///// ECDH
	// For the computation of shared secrets using the secp256r1/NIST-P256 curve. Note: much of the 
	// ECC functionality is shared between ECDSA and ECDH, but seperate functions are given 
	// nonetheless. All given crypto implementations use a shared ECC implementation.
	//
	// Public keys are only ever stored and transmitted with only the X component. The Y component can
	// be derived as long as it's even-ness is provided, but in our case we skip this by requiring public
	// keys with an even Y component. For doing this, each time a key is generated it is tested, and if
	// an odd public key is generated it is discarded.
	//
	// Signatures are always serialized without any encoding, with the R and S components stored one after
	// the other as 256 bit numbers. Some multi-precision libraries tend to pad zeroes in front even
	// if it is not needed. For us EC point components are always 256 bits when stored or transmitted.
	//
	// When storing and loading an ECDH or ECDSA context, the format and nature of storage is left up to
	// the implementation, but typically the private key is stored. These functions are provided for the
	// case where private information is stored in a trusted platform module. In this case it is assumed
	// that some information will be stored so that the context can be restored and used.
	//
	// When deriving a shared secret, no operations may be performed on the result of the computation.
	// Some ECDH implementation will automatically perform a SHA or ECDH operation, or require you
	// to provide some operation to perform. This must not be done as MR will always SHA the output
	// of mr_ecdh_derivekey.
	//
	// Similarly when signing messages, the input to the signature function will not be the message itself
	// but the SHA256 digest of the message.

	// create a new ECDH context.
	mr_ecdh_ctx mr_ecdh_create(mr_ctx mr_ctx);
	// generate keys for an ECDH context. The generated public key Y component must be even.
	mr_result mr_ecdh_generate(mr_ecdh_ctx ctx, uint8_t* publickey, uint32_t publickeyspaceavail);
	// load a stored ECDH context.
	uint32_t mr_ecdh_load(mr_ecdh_ctx ctx, const uint8_t* data, uint32_t spaceavail);
	// derive a shared key given another ECDH public key.
	mr_result mr_ecdh_derivekey(mr_ecdh_ctx ctx, const uint8_t* otherpublickey, uint32_t otherpublickeysize, uint8_t* derivedkey, uint32_t derivedkeyspaceavail);
	// return the size needed to store an ECDH context.
	uint32_t mr_ecdh_store_size_needed(mr_ecdh_ctx ctx);
	// store an ECDH ontext.
	mr_result mr_ecdh_store(mr_ecdh_ctx ctx, uint8_t* data, uint32_t spaceavail);
	// set the private key for an ECDH context. This is mainly for testing.
	mr_result mr_ecdh_setprivatekey(mr_ecdh_ctx ctx, const uint8_t* privatekey, uint32_t privatekeysize);
	// derive the public key for an ECDH context.
	mr_result mr_ecdh_getpublickey(mr_ecdh_ctx ctx, uint8_t* publickey, uint32_t publickeyspaceavail);
	// free an ECDH context.
	void mr_ecdh_destroy(mr_ecdh_ctx ctx);


	///// ECDSA
	// For the computation of signatures using the secp256r1/NIST-P256 curve. See notes
	// above for more information.

	// create a new ECDSA context.
	mr_ecdsa_ctx mr_ecdsa_create(mr_ctx mr_ctx);
	// set the private key for an ECDSA context. This is mainly for testing.
	mr_result mr_ecdsa_setprivatekey(mr_ecdsa_ctx ctx, const uint8_t* privatekey, uint32_t privatekeysize);
	// derive the public key for an ECDSA context.
	mr_result mr_ecdsa_getpublickey(mr_ecdsa_ctx ctx, uint8_t* publickey, uint32_t publickeyspaceavail);
	// generate keys for an ECDSA context. The generated public key Y component must be even.
	mr_result mr_ecdsa_generate(mr_ecdsa_ctx ctx, uint8_t* publickey, uint32_t publickeyspaceavail);
	// load a stored ECDSA context.
	uint32_t mr_ecdsa_load(mr_ecdsa_ctx ctx, const uint8_t* data, uint32_t spaceavail);
	// compute an ECDSA signature given a 256 bit message digest.
	mr_result mr_ecdsa_sign(mr_ecdsa_ctx ctx, const uint8_t* digest, uint32_t digestsize, uint8_t* signature, uint32_t signaturespaceavail);
	// return the size needed to store an ECDSA context.
	uint32_t mr_ecdsa_store_size_needed(mr_ecdsa_ctx ctx);
	// store an ECDSA ontext.
	mr_result mr_ecdsa_store(mr_ecdsa_ctx ctx, uint8_t* data, uint32_t spaceavail);
	// free an ECDSA context.
	void mr_ecdsa_destroy(mr_ecdsa_ctx ctx);
	// verify an ECDSA signed message given a public key and a message digest.
	mr_result mr_ecdsa_verify_other(const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, const uint8_t* publickey, uint32_t publickeysize, uint32_t* result);


	///// RNG
	// For the generation of random numbers, usually for nonces and for some implementations
	// for the generation of signatures and ECDH keys. Random number generation is not called
	// very often so using an entropy source directly is usually sufficient (e.g. x64 rdseed64 or STM32 RNG)
	// Crypto libraries will typically provide a PRNG/DRBG seeded by a true random number (see mr_rng_seed below).
	// In some of the provided crypto implementations this is used.
	//
	// In MR random numbers are generated in small amounts (typically 16 bytes at a time) relatively infrequently 
	// (not even every message) so that using a PRNG will be slower or the same in the whole. Not to mention
	// the increase in code size and memory for embedded systems.

	// create a new RNG context.
	mr_rng_ctx mr_rng_create(mr_ctx mr_ctx);
	// generate random numbers. outputsize will typically be 16 or 32 bytes. It can safely
	// be required to be 4 bytes aligned in size and address.
	mr_result mr_rng_generate(mr_rng_ctx ctx, uint8_t* output, uint32_t outputsize);
	// free an RNG context.
	void mr_rng_destroy(mr_rng_ctx ctx);








	///// PLATFORM FUNCTIONS
	// these functions need to be provided by the integrating application.

	// get a few random numbers from somewhere. This is for crypto libraries
	// that do not have non-deterministic random number generation and will only
	// ever be called from a crypto library. An example x64 implementation
	// is given in microratchettests/rng.cpp
	mr_result mr_rng_seed(uint8_t* output, uint32_t sz);
	// allocate memory. mr_ctx is generally provided but could be null (for example
	// when called from mr_ctx_create).
	mr_result mr_allocate(mr_ctx ctx, int amountrequested, void** pointer);
	// free memory allocated with mr_allocate.
	void mr_free(mr_ctx ctx, void* pointer);







	/////////////////////////////////////
	// DIRECT IMPLEMENTATION FUNCTIONS //
	/////////////////////////////////////

	// Call these functions from your application.
	//
	// To use MR, first you need to create a context. Configuration contains the application key and whether
	// or not this is a client or server. The application key is not required to be secret but rather provided
	// to make different MR applications incompatible. However, if the application key is secret, MR messages
	// will typically not be identifyable.
	//
	// Once a context is created, its identity must be set before data can be processed. The identity of a
	// context is an ECDSA key pair created or loaded using the ECDSA functions.
	//
	// After the identity is set, data can be transmitted and received. The main loop of an MR application
	// consists of:
	//   1) initiating the session (in the case of client) - mr_ctx_initiate_initialization
	//   2) loop -
	//      a) receive any messages received
	//      b) passing the message to mr_ctx_receive
	//      c) if mr_ctx_receive receives an initialization message it will return MR_SENDBACK.
	//         in this case the application must send back the payload.
	//         if mr_ctx_receive receives application data, payload will contain the decrypted data.
	//   3) when sending data, pass it to mr_ctx_send. This will encrypt a message to be sent.
	//
	// Notes:
	// - messages are processed *in place*. This means if you receive a message, the payload pointer returned
	//   will be *inside* the message passed in, and the encrypted data from the message will be overwritten.
	//   This also means that when sending a payload, the buffer that contains the payload must be bigger than
	//   the payload itself by at least 16 bytes. The encrypted message to send will overwrite the unencrypted
	//   message in place.
	// - messages are always padded (with zeroes) if needed and no size information is transmitted. This means that although
	//   the buffer for sending a message must be at least 16 bytes larger, it can in practice be any size (limited by
	//   the MTU of whatever message protocol is used). This does mean, however, that when receiving a message it
	//   cannot be assumed that the message would not have been padded. When choosing an message encoding or decoding
	//   scheme be sure to either provide the length inside the message payload or use an encoding that will automatically
	//   terminate upon hitting an unexpected 0.
	// - for transferring messages over the internet, an MTU of ~1k is advised to make sure a packet doesn't exceed the
	//   Ethernet MTU of 1500 bytes. If very large (>1k && <64k) messages are required it is advisable to 
	//   implement fragmentation and re-assembly INSIDE your system rather than leaving this up to something
	//   else like UDP or IP.
	// - If your messages are larger than 64k you should probably be using TLS.
	// - If you are considering using TCP, you should also probably consider TLS or DTLS as both maintain the streaming semantics of TCP.
	// - some of the padded space may be used for transferring a new ECDH key. This is only done if there is enough space
	//   so if your messages are often packed to the brim, you might want to send an empty message every now and again to
	//   facilitate ECDH ratcheting (and thereby forward-secrecy). See the comments above mr_ctx_send for how this works.

	// create a new MicroRatchet context with the provided configuration. the client will hold a reference to the configuration.
	mr_ctx mr_ctx_create(const mr_config* config);

	// set the identity of a context. Must be done before initialization but need not be done
	// if initialization has already taken place. If destroy_with_context is true, the ecdsa object
	// will be freed along with the context when the context is destroyed.
	mr_result mr_ctx_set_identity(mr_ctx ctx, mr_ecdsa_ctx identity, bool destroy_with_context);

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

	// indicates whether or not the context is initialized and data can be sent and received.
	mr_result mr_ctx_is_initialized(mr_ctx ctx, bool* initialized);

	// destroys a context and frees all related memory. The identity ECDH object
	// will not be destroyed.
	void mr_ctx_destroy(mr_ctx ctx);


	//////////////////////////
	// HIGH-LEVEL FUNCTIONS //
	//////////////////////////

	// run the main loop for MicroRatchet. Will block until mr_hl_deactivate is called
	// from another thread.
	mr_result mr_hl_mainloop(mr_ctx ctx, const mr_hl_config* config);

	// performs initialization.
	// If timeout is 0, the action will execute asynchronously and MR_E_ACTION_ENQUEUED will be returned.
	mr_result mr_hl_initialize(mr_ctx ctx, uint32_t timeout);

	// buffers a message to send.
	// If timeout is 0, the action will execute asynchronously and MR_E_ACTION_ENQUEUED will be returned.
	mr_result mr_hl_send(mr_ctx ctx, const uint8_t* data, const uint32_t size, uint32_t timeout);

	// notifies the main loop that data is available. 
	// config->receive will be called to retrieve the data.
	// available specifies the number of bytes available.
	// If timeout is 0, the action will execute asynchronously and MR_E_ACTION_ENQUEUED will be returned.
	mr_result mr_hl_receive(mr_ctx ctx, uint32_t available, uint32_t timeout);

	// notifies the main loop that data is available.
	// config->receive will NOT be called to retrieve the data, the data provided will be used.
	// If timeout is 0, the action will execute asynchronously and MR_E_ACTION_ENQUEUED will be returned.
	mr_result mr_hl_receive_data(mr_ctx ctx, const uint8_t* data, uint32_t size, uint32_t timeout);

	// Causes the main loop to exit.
	// If timeout is 0, the action will execute asynchronously and MR_E_ACTION_ENQUEUED will be returned.
	mr_result mr_hl_deactivate(mr_ctx ctx, uint32_t timeout);

#ifdef __cplusplus
}
#endif