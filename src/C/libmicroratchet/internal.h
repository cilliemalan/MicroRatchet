#pragma once

#include "microratchet.h"


#define HAS_SERVER


#if defined(_DEBUG) && !defined(DEBUG)
#define DEBUG
#endif

#if defined(_MSC_VER)
#define STATIC_ASSERT(e, r) static_assert(e, r)
#elif defined(__GNUC__)
#define STATICASSERT(e,r) _Static_assert(e, r)
#else
#define STATICASSERT(e, r)
#endif


#ifdef __cplusplus
extern "C" {
#endif

#define KEY_SIZE 32
#define MSG_KEY_SIZE 16
#define INITIALIZATION_NONCE_SIZE 16
#define NONCE_SIZE 4
#define MAC_SIZE 12
#define ECNUM_SIZE 32
#define SIGNATURE_SIZE (ECNUM_SIZE+ECNUM_SIZE)
#define NUM_RATCHETS 5
#define HEADERIV_SIZE 16
#define DIGEST_SIZE 32
#define MACIV_SIZE 32
#define MIN_MSG_SIZE (HEADERIV_SIZE)
#define MIN_OVERHEAD (NONCE_SIZE + MAC_SIZE)
#define OVERHEAD_WITH_ECDH (MIN_OVERHEAD + ECNUM_SIZE)
#define INIT_REQ_MSG_SIZE (NONCE_SIZE + ECNUM_SIZE*2 + SIGNATURE_SIZE)
#define INIT_RES_MSG_SIZE (NONCE_SIZE*2 + ECNUM_SIZE*4 + SIGNATURE_SIZE + MAC_SIZE)
#define MINIMUMPAYLOAD_SIZE (INITIALIZATION_NONCE_SIZE)
#define MINIMUMOVERHEAD (NONCE_SIZE + MAC_SIZE) // 16
#define OVERHEADWITHECDH (MINIMUMOVERHEAD + ECNUM_SIZE) // 48
#define MINIMUMMESSAGE_SIZE (MINIMUMPAYLOAD_SIZE + MINIMUMOVERHEAD)
#define MINIMUMMAXIMUMMESSAGE_SIZE (OVERHEADWITHECDH + MINIMUMPAYLOAD_SIZE)

#define _C(x) { int __r = x; if(__r != E_SUCCESS) return __r; }
#define _N(x, mr_ctx, ctx) { int __r = x; if(__r != E_SUCCESS) { ctx->next(__r, ctx, mr_ctx); return; } }
#define _E(x, mr_ctx, ctx) { int __r = x; if(__r != E_SUCCESS) { (mr_ctx->next = ctx->next)(__r, ctx, mr_ctx); return; } }

	typedef struct _mr_initialization_state {
		union {
#ifdef HAS_SERVER
			struct server {
				uint8_t nextinitializationnonce[INITIALIZATION_NONCE_SIZE];
				uint8_t rootkey[KEY_SIZE];
				uint8_t firstsendheaderkey[KEY_SIZE];
				uint8_t firstreceiveheaderkey[KEY_SIZE];
				mr_ecdh_ctx localratchetstep0;
				mr_ecdh_ctx localratchetstep1;
				uint8_t clientpublickey[ECNUM_SIZE];
			} server;
#endif
			struct client {
				uint8_t initializationnonce[INITIALIZATION_NONCE_SIZE];
				mr_ecdh_ctx localecdhforinit;
			} client;
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
	} _mr_ctx;

	typedef struct _mr_aesctr_ctx {
		mr_aes_ctx aes_ctx;
		uint8_t ctr[16];
	} _mr_aesctr_ctx;


	// AES KDF
	int kdf_compute(mr_ctx mr_ctx, const uint8_t* key, uint32_t keylen, const uint8_t* info, uint32_t infolen, uint8_t* output, uint32_t spaceavail);

	// AES CTR
	int aesctr_init(_mr_aesctr_ctx* ctx, mr_aes_ctx aes, const uint8_t* iv, uint32_t ivsize);
	int aesctr_process(_mr_aesctr_ctx* ctx, const uint8_t* data, uint32_t amount, uint8_t* output, uint32_t spaceavail);

	// some bit movings
	void be_pack64(long long value, uint8_t* target);
	void be_pack32(int value, uint8_t* target);
	void be_pack16(short value, uint8_t* target);
	void le_pack64(long long value, uint8_t* target);
	void le_pack32(int value, uint8_t* target);
	void le_pack16(short value, uint8_t* target);
	long long be_unpack64(const uint8_t* d);
	int be_unpack32(const uint8_t* d);
	short be_unpack16(const uint8_t* d);
	long long le_unpack64(const uint8_t* d);
	int le_unpack32(const uint8_t* d);
	short le_unpack16(const uint8_t* d);

	// ratchetings
	mr_result_t ratchet_getorder(mr_ctx mr_ctx, int* indexes, uint32_t numindexes);
	mr_result_t ratchet_getoldest(mr_ctx mr_ctx, _mr_ratchet_state** ratchet);
	mr_result_t ratchet_getsecondtolast(mr_ctx mr_ctx, _mr_ratchet_state** ratchet);
	mr_result_t ratchet_getlast(mr_ctx mr_ctx, _mr_ratchet_state** ratchet);
	mr_result_t ratchet_add(mr_ctx mr_ctx, const _mr_ratchet_state* ratchet);
	mr_result_t ratchet_initialize_server(mr_ctx mr_ctx,
		_mr_ratchet_state* ratchet,
		mr_ecdh_ctx previouskeypair,
		const uint8_t* rootkey, uint32_t rootkeysize,
		const uint8_t* remotepubickey, uint32_t remotepubickeysize,
		mr_ecdh_ctx keypair,
		const uint8_t* receiveheaderkey, uint32_t receiveheaderkeysize,
		const uint8_t* sendheaderkey, uint32_t sendheaderkeysize);
	mr_result_t ratchet_initialize_client(mr_ctx mr_ctx,
		_mr_ratchet_state* ratchet1,
		_mr_ratchet_state* ratchet2,
		const uint8_t* rootkey, uint32_t rootkeysize,
		const uint8_t* remotepubickey0, uint32_t remotepubickey0size,
		const uint8_t* remotepubickey1, uint32_t remotepubickey1size,
		mr_ecdh_ctx keypair,
		const uint8_t* receiveheaderkey, uint32_t receiveheaderkeysize,
		const uint8_t* sendheaderkey, uint32_t sendheaderkeysize,
		mr_ecdh_ctx nextkeypair);
	mr_result_t ratchet_initialize(
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
	mr_result_t ratchet_ratchet(mr_ctx mr_ctx, _mr_ratchet_state* ratchet, _mr_ratchet_state* nextratchet, const uint8_t* remotepublickey, uint32_t remotepublickeysize, mr_ecdh_ctx keypair);
	mr_result_t chain_initialize(mr_ctx mr_ctx, _mr_chain_state* chain_state, const uint8_t* chainkey, uint32_t chainkeysize);
	mr_result_t chain_ratchetforsending(mr_ctx mr_ctx, _mr_chain_state* chain, uint8_t* key, uint32_t keysize, uint32_t* generation);
	mr_result_t chain_ratchetforreceiving(mr_ctx mr_ctx, _mr_chain_state* chain, uint32_t generation, uint8_t* key, uint32_t keysize);






#ifdef DEBUG
#include <stdio.h>
void _mrlog(const char* msg, const uint8_t* data, uint32_t amt);
#define LOG(msg) printf("%s\n", msg)
#define LOGD(msg, data, amt) _mrlog(msg, data, amt)
#else
#define LOG(msg)
#define LOGD(msg, data, amt)
#endif



#ifdef __cplusplus
}
#endif