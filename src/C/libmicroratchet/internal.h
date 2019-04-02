#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define KEY_SIZE 32
#define MSG_KEY_SIZE 16
#define NONCE_SIZE 4
#define MAC_SIZE 12
#define ECNUM_SIZE 12
#define NUM_RATCHETS 5
#define NUM_LOST_KEYS 10


#define _C(x) { int __r = x; if(__r != E_SUCCESS) return __r; }
#define _N(x, mr_ctx, ctx) { int __r = x; if(__r != E_SUCCESS) { ctx->next(__r, ctx, mr_ctx); return; } }
#define _E(x, mr_ctx, ctx) { int __r = x; if(__r != E_SUCCESS) { (mr_ctx->next = ctx->next)(__r, ctx, mr_ctx); return; } }

	typedef struct _mr_ctx {
		mr_config* config;
		mr_sha_ctx sha_ctx;
		_mr_initialization_state init;
		_mr_ratchet_state ratchets[NUM_RATCHETS];
		_mr_lostkey lost_keys[NUM_LOST_KEYS];
	} _mr_ctx;

	typedef struct _mr_initialization_state {
		union {
			struct server {
				unsigned char nextinitializationnonce[NONCE_SIZE];
				unsigned char rootkey[KEY_SIZE];
				unsigned char firstsendheaderkey[KEY_SIZE];
				unsigned char firstreceiveheaderkey[KEY_SIZE];
				mr_ecdh_ctx localratchetstep0;
				mr_ecdh_ctx localratchetstep1;
				unsigned char clientpublickey[ECNUM_SIZE];
			} server;
			struct client {
				unsigned char initializationnonce[NONCE_SIZE];
				mr_ecdh_ctx localecdhforinit;
			} client;
		};
	} _mr_initialization_state;

	typedef struct _mr_lostkey {
		_mr_chain_state* chain;
		unsigned int generation;
		unsigned char key[MSG_KEY_SIZE];
	} _mr_lostkey;

	typedef struct _mr_chain_state {
		unsigned int generation;
		unsigned char nextheaderkey[KEY_SIZE];
		unsigned char headerkey[KEY_SIZE];
		unsigned char chainkey[KEY_SIZE];
	} _mr_chain_state;

	typedef struct _mr_ratchet_state {
		mr_ecdh_ctx ecdhkey;
		unsigned char nextrootkey[KEY_SIZE];
		_mr_chain_state sendingchain;
		_mr_chain_state receivingchain;
	} _mr_ratchet_state;



	typedef struct _mr_aesctr_ctx {
		mr_aes_ctx aes_ctx;
		unsigned char ctr[16];
	} _mr_aesctr_ctx;


	// AES KDF
	int kdf_compute(mr_ctx mr_ctx, const unsigned char* key, unsigned int keylen, const unsigned char* info, unsigned int infolen, unsigned char* output, unsigned int spaceavail);

	// AES CTR
	int aesctr_init(_mr_aesctr_ctx *ctx, mr_aes_ctx aes, const unsigned char *iv, unsigned int ivsize);
	int aesctr_process(_mr_aesctr_ctx *ctx, const unsigned char* data, unsigned int amount, unsigned char* output, unsigned int spaceavail);


#ifdef __cplusplus
}
#endif