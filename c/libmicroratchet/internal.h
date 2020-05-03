#pragma once

#include "microratchet.h"

#define HAS_SERVER

#if defined(MR_DEBUG) && !defined(DEBUG)
#define DEBUG
#endif

#if defined(_MSC_VER)
#define STATIC_ASSERT(e, r) static_assert(e, r)
#elif defined(__GNUC__)
#define STATIC_ASSERT(e,r) _Static_assert(e, r)
#else
#define STATIC_ASSERT(e, r)
#endif

#define KEY_SIZE 32
#define MSG_KEY_SIZE 16
#define INITIALIZATION_NONCE_SIZE 16
#define NONCE_SIZE 4
#define MAC_SIZE 12
#define ECNUM_SIZE 32
#define SIGNATURE_SIZE (ECNUM_SIZE  +ECNUM_SIZE)
#define NUM_RATCHETS 5
#define HEADERIV_SIZE 16
#define DIGEST_SIZE 32
#define MACIV_SIZE 16
#define MIN_PAYLOAD_SIZE (HEADERIV_SIZE)
#define OVERHEAD_WITHOUT_ECDH (NONCE_SIZE + MAC_SIZE)
#define OVERHEAD_WITH_ECDH (OVERHEAD_WITHOUT_ECDH + ECNUM_SIZE)
#define INIT_REQ_MSG_SIZE (NONCE_SIZE + ECNUM_SIZE*2 + SIGNATURE_SIZE + MAC_SIZE)
#define INIT_RES_MSG_SIZE (NONCE_SIZE*2 + ECNUM_SIZE*4 + SIGNATURE_SIZE + MAC_SIZE)
#define MIN_MESSAGE_SIZE (OVERHEAD_WITHOUT_ECDH + MIN_PAYLOAD_SIZE)
#define MIN_MESSAGE_SIZE_WITH_ECDH (OVERHEAD_WITH_ECDH + MIN_PAYLOAD_SIZE)

#ifdef _C
#undef _C
#endif

#ifdef _R
#undef _R
#endif

// check the result and return if not successful
#define _C(x) do { int __r = x; if(__r != MR_E_SUCCESS) return __r; } while (0)

// if (r == success) r = x
#define _R(r, x) do { if (r == MR_E_SUCCESS) r = x; } while (0)

	typedef struct _mr_initialization_state_server {
		uint8_t nextinitializationnonce[INITIALIZATION_NONCE_SIZE];
		// the order of these is important
		uint8_t rootkey[KEY_SIZE];
		uint8_t firstsendheaderkey[KEY_SIZE];
		uint8_t firstreceiveheaderkey[KEY_SIZE];

		mr_ecdh_ctx localratchetstep0;
		mr_ecdh_ctx localratchetstep1;
		uint8_t clientpublickey[ECNUM_SIZE];
	} _mr_initialization_state_server;

	typedef struct _mr_initialization_state_client {
		uint8_t initializationnonce[INITIALIZATION_NONCE_SIZE];
		mr_ecdh_ctx localecdhforinit;
	} _mr_initialization_state_client;

	typedef struct _mr_initialization_state {
		bool initialized;
		union {
#ifdef HAS_SERVER
			_mr_initialization_state_server* server;
#endif
			_mr_initialization_state_client* client;
		};
	} _mr_initialization_state;

	typedef struct _mr_chain_state {
		uint32_t generation;
		uint8_t chainkey[KEY_SIZE];
		uint32_t oldgeneration;
		uint8_t oldchainkey[KEY_SIZE];
	} _mr_chain_state;

	typedef struct _mr_ratchet_state {
		uint32_t num;
		mr_ecdh_ctx ecdhkey;
		uint8_t nextrootkey[KEY_SIZE];
		uint8_t sendheaderkey[KEY_SIZE];
		uint8_t nextsendheaderkey[KEY_SIZE];
		uint8_t receiveheaderkey[KEY_SIZE];
		uint8_t nextreceiveheaderkey[KEY_SIZE];
		_mr_chain_state sendingchain;
		_mr_chain_state receivingchain;
	} _mr_ratchet_state;

	typedef struct s_mr_ctx {
		mr_config config;
		mr_sha_ctx sha_ctx;
		mr_rng_ctx rng_ctx;
		_mr_initialization_state init;
		_mr_ratchet_state ratchets[NUM_RATCHETS];
		mr_ecdsa_ctx identity;
		bool owns_identity;
	} _mr_ctx;

	typedef struct _mr_aesctr_ctx {
		mr_aes_ctx aes_ctx;
		uint8_t ctr[16];
		uint32_t ctrix;
	} _mr_aesctr_ctx;

#ifdef __cplusplus
	extern "C" {
#endif

	// AES KDF
	mr_result kdf_compute(mr_ctx mr_ctx, const uint8_t* key, uint32_t keylen, const uint8_t* info, uint32_t infolen, uint8_t* output, uint32_t spaceavail);

	// AES CTR
	mr_result aesctr_init(_mr_aesctr_ctx* ctx, mr_aes_ctx aes, const uint8_t* iv, uint32_t ivsize);
	mr_result aesctr_process(_mr_aesctr_ctx* ctx, const uint8_t* data, uint32_t amount, uint8_t* output, uint32_t spaceavail);

	// ratchetings
	mr_result ratchet_getorder(mr_ctx mr_ctx, int* indexes, uint32_t numindexes);
	mr_result ratchet_getoldest(mr_ctx mr_ctx, _mr_ratchet_state** ratchet);
	mr_result ratchet_getsecondtolast(mr_ctx mr_ctx, _mr_ratchet_state** ratchet);
	mr_result ratchet_getlast(mr_ctx mr_ctx, _mr_ratchet_state** ratchet);
	mr_result ratchet_add(mr_ctx mr_ctx, _mr_ratchet_state* ratchet);
	bool ratchet_destroy(_mr_ctx* ctx, int num);
	mr_result ratchet_initialize_server(mr_ctx mr_ctx,
		_mr_ratchet_state* ratchet,
		mr_ecdh_ctx previouskeypair,
		const uint8_t* rootkey, uint32_t rootkeysize,
		const uint8_t* remotepubickey, uint32_t remotepubickeysize,
		mr_ecdh_ctx keypair,
		const uint8_t* receiveheaderkey, uint32_t receiveheaderkeysize,
		const uint8_t* sendheaderkey, uint32_t sendheaderkeysize);
	mr_result ratchet_initialize_client(mr_ctx mr_ctx,
		_mr_ratchet_state* ratchet1,
		_mr_ratchet_state* ratchet2,
		const uint8_t* rootkey, uint32_t rootkeysize,
		const uint8_t* remotepubickey0, uint32_t remotepubickey0size,
		const uint8_t* remotepubickey1, uint32_t remotepubickey1size,
		mr_ecdh_ctx keypair,
		const uint8_t* receiveheaderkey, uint32_t receiveheaderkeysize,
		const uint8_t* sendheaderkey, uint32_t sendheaderkeysize,
		mr_ecdh_ctx nextkeypair);
	mr_result ratchet_initialize(
		mr_ctx mr_ctx,
		_mr_ratchet_state* ratchet,
		uint32_t num,
		mr_ecdh_ctx ecdhkey,
		const uint8_t* nextrootkey, uint32_t nextrootkeysize,
		uint32_t receivinggeneration,
		const uint8_t* receivingheaderkey, uint32_t receivingheaderkeysize,
		const uint8_t* receivingnextheaderkey, uint32_t receivingnextheaderkeysize,
		const uint8_t* receivingchainkey, uint32_t receivingchainkeysize,
		uint32_t sendinggeneration,
		const uint8_t* sendingheaderkey, uint32_t sendingheaderkeysize,
		const uint8_t* sendingnextheaderkey, uint32_t sendingnextheaderkeysize,
		const uint8_t* sendingchainkey, uint32_t sendingchainkeysize);
	mr_result ratchet_ratchet(mr_ctx mr_ctx, _mr_ratchet_state* ratchet, _mr_ratchet_state* nextratchet, const uint8_t* remotepublickey, uint32_t remotepublickeysize, mr_ecdh_ctx keypair);
	mr_result chain_initialize(mr_ctx mr_ctx, _mr_chain_state* chain_state, const uint8_t* chainkey, uint32_t chainkeysize);
	mr_result chain_ratchetforsending(mr_ctx mr_ctx, _mr_chain_state* chain, uint8_t* key, uint32_t keysize, uint32_t* generation);
	mr_result chain_ratchetforreceiving(mr_ctx mr_ctx, _mr_chain_state* chain, uint32_t generation, uint8_t* key, uint32_t keysize);

#ifdef __cplusplus
}
#endif


// fail messages to fail a function with a reason message
#if defined(MR_WRITE) && defined(MR_DEBUG)

#define MR_STRINGIZE(x) MR_STRINGIZE2(x)
#define MR_STRINGIZE2(x) #x
#define __LINE_STRING__ MR_STRINGIZE(__LINE__)

#define MR_WRITE1(msg) do { static const char __msg[] = msg; MR_WRITE(msg, sizeof(msg) - 1); } while(0)

#define FAILIF(condition, error, messageonfailure) if (condition) { MR_WRITE1(__FILE__ ":" __LINE_STRING__ " " messageonfailure); return (error); }
#define FAILMSG(error, messageonfailure) MR_WRITE1(__FILE__ ":" __LINE_STRING__ " " messageonfailure); return (error);
#else
#define FAILIF(condition, error, messageonfailure) if (condition) { return (error); }
#define FAILMSG(error, messageonfailure) return (error);
#endif

// trace messages to debug crypto internals
#if defined(MR_TRACE) && defined (MR_WRITE)
void _mrlog(const char* msg, uint32_t msglen, const uint8_t* data, uint32_t datalen);
#define LOG(msg) _mrlog(msg, sizeof(msg) - 1, 0, 0)
#define LOGD(msg, data, amt) _mrlog(msg, sizeof(msg) - 1, data, amt)
#else
#define LOG(msg)
#define LOGD(msg, data, amt)
#endif

