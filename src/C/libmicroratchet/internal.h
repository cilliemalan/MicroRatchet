#pragma once

#include "microratchet.h"


#ifdef __cplusplus
extern "C" {
#endif

#define STATICASSERT(ex,msg) static_assert(ex,msg)

#define KEY_SIZE 32
#define MSG_KEY_SIZE 16
#define NONCE_SIZE 4
#define MAC_SIZE 12
#define ECNUM_SIZE 32
#define SIGNATURE_SIZE (ECNUM_SIZE+ECNUM_SIZE)
#define NUM_RATCHETS 5
#define NUM_LOST_KEYS 10
#define MIN_MSG_SIZE 16
#define MIN_MSG_SIZE 16
#define MIN_OVERHEAD (NONCE_SIZE + MAC_SIZE)
#define OVERHEAD_WITH_ECDH (MIN_OVERHEAD + ECNUM_SIZE)
#define INIT_REQ_MSG_SIZE (NONCE_SIZE + ECNUM_SIZE*2 + SIGNATURE_SIZE)
#define INIT_RES_MSG_SIZE (NONCE_SIZE*2 + ECNUM_SIZE*4 + SIGNATURE_SIZE + MAC_SIZE)

#define MSG_TYPE_NORMAL 0
#define MSG_TYPE_NORMAL_WITH_ECDH 1
// 2 = reserved
#define MSG_TYPE_MULTIPART 3
#define MSG_TYPE_INIT_REQ 4
#define MSG_TYPE_INIT_WITHOUT_ECDH 4
#define MSG_TYPE_INIT_RES 5
#define MSG_TYPE_INIT_WITH_ECDH 5
// 6 = reserved
// 7 = reserved


#define _C(x) { int __r = x; if(__r != E_SUCCESS) return __r; }
#define _N(x, mr_ctx, ctx) { int __r = x; if(__r != E_SUCCESS) { ctx->next(__r, ctx, mr_ctx); return; } }
#define _E(x, mr_ctx, ctx) { int __r = x; if(__r != E_SUCCESS) { (mr_ctx->next = ctx->next)(__r, ctx, mr_ctx); return; } }

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

	typedef struct _mr_chain_state {
		unsigned int generation;
		unsigned char nextheaderkey[KEY_SIZE];
		unsigned char headerkey[KEY_SIZE];
		unsigned char chainkey[KEY_SIZE];
	} _mr_chain_state;

	typedef struct _mr_lostkey {
		unsigned int ratchet;
		unsigned int generation;
		unsigned char key[MSG_KEY_SIZE];
	} _mr_lostkey;

	typedef struct _mr_ratchet_state {
		unsigned int num;
		mr_ecdh_ctx ecdhkey;
		unsigned char nextrootkey[KEY_SIZE];
		_mr_chain_state sendingchain;
		_mr_chain_state receivingchain;
	} _mr_ratchet_state;

	typedef struct _mr_ctx {
		mr_config* config;
		mr_sha_ctx sha_ctx;
		_mr_initialization_state init;
		_mr_ratchet_state ratchets[NUM_RATCHETS];
		_mr_lostkey lost_keys[NUM_LOST_KEYS];
	} _mr_ctx;

	typedef struct _mr_aesctr_ctx {
		mr_aes_ctx aes_ctx;
		unsigned char ctr[16];
	} _mr_aesctr_ctx;


	// AES KDF
	int kdf_compute(mr_ctx mr_ctx, const unsigned char* key, unsigned int keylen, const unsigned char* info, unsigned int infolen, unsigned char* output, unsigned int spaceavail);

	// AES CTR
	int aesctr_init(_mr_aesctr_ctx * ctx, mr_aes_ctx aes, const unsigned char* iv, unsigned int ivsize);
	int aesctr_process(_mr_aesctr_ctx * ctx, const unsigned char* data, unsigned int amount, unsigned char* output, unsigned int spaceavail);

	// some bit movings
	void be_pack64(long long value, unsigned char* target);
	void be_pack32(int value, unsigned char* target);
	void be_pack16(short value, unsigned char* target);
	void le_pack64(long long value, unsigned char* target);
	void le_pack32(int value, unsigned char* target);
	void le_pack16(short value, unsigned char* target);
	long long be_unpack64(const unsigned char* d);
	int be_unpack32(const unsigned char* d);
	short be_unpack16(const unsigned char* d);
	long long le_unpack64(const unsigned char* d);
	int le_unpack32(const unsigned char* d);
	short le_unpack16(const unsigned char* d);

	// ratchetings
	int ratchet_getorder(mr_ctx mr_ctx, int* indexes, unsigned int numindexes);
	int ratchet_getoldest(mr_ctx mr_ctx, _mr_ratchet_state** ratchet);
	int ratchet_getsecondtolast(mr_ctx mr_ctx, _mr_ratchet_state** ratchet);
	int ratchet_getlast(mr_ctx mr_ctx, _mr_ratchet_state** ratchet);
	int ratchet_initialize_server(mr_ctx mr_ctx,
		_mr_ratchet_state* ratchet,
		mr_ecdh_ctx previouskeypair,
		unsigned char* rootkey, unsigned int rootkeysize,
		unsigned char* remotepubickey, unsigned int remotepubickeysize,
		mr_ecdh_ctx keypair,
		unsigned char* receiveheaderkey, unsigned int receiveheaderkeysize,
		unsigned char* sendheaderkey, unsigned int sendheaderkeysize);
	int ratchet_initialize_client(mr_ctx mr_ctx,
		_mr_ratchet_state* ratchet1,
		_mr_ratchet_state* ratchet2,
		unsigned char* rootkey, unsigned int rootkeysize,
		unsigned char* remotepubickey0, unsigned int remotepubickey0size,
		unsigned char* remotepubickey1, unsigned int remotepubickey1size,
		mr_ecdh_ctx keypair,
		unsigned char* receiveheaderkey, unsigned int receiveheaderkeysize,
		unsigned char* sendheaderkey, unsigned int sendheaderkeysize,
		mr_ecdh_ctx nextkeypair);
	int ratchet_initialize(
		mr_ctx mr_ctx,
		_mr_ratchet_state* ratchet,
		unsigned int num,
		mr_ecdh_ctx ecdhkey,
		unsigned char* nextrootkey, unsigned int nextrootkeysize,
		unsigned int receivinggeneration,
		unsigned char* receivingheaderkey, unsigned int receivingheaderkeysize,
		unsigned char* receivingnextheaderkey, unsigned int receivingnextheaderkeysize,
		unsigned char* receivingchainkey, unsigned int receivingchainkeysize,
		unsigned int sendinggeneration,
		unsigned char* sendingheaderkey, unsigned int sendingheaderkeysize,
		unsigned char* sendingnextheaderkey, unsigned int sendingnextheaderkeysize,
		unsigned char* sendingchainkey, unsigned int sendingchainkeysize);
	int ratchet_ratchet(mr_ctx mr_ctx, _mr_ratchet_state* ratchet, _mr_ratchet_state* nextratchet, unsigned char* remotepublickey, unsigned int remotepublickeysize, mr_ecdh_ctx keypair);
	int chain_initialize(mr_ctx mr_ctx, _mr_chain_state* chain_state, const unsigned char* headerkey, unsigned int headerkeysize, const unsigned char* chainkey, unsigned int chainkeysize, const unsigned char* nextheaderkey, unsigned int nextheaderkeysize);
	int chain_ratchetforsending(mr_ctx mr_ctx, _mr_ratchet_state* ratchet, unsigned char* key, unsigned int keysize, int* generation);
	int chain_ratchetforreceiving(mr_ctx mr_ctx, _mr_ratchet_state* ratchet, unsigned int generation, unsigned char* key, unsigned int keysize);

#ifdef __cplusplus
}
#endif