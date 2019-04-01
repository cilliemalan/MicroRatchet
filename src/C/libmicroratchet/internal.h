#pragma once

#ifdef __cplusplus
extern "C" {
#endif


#define _C(x) { int __r = x; if(__r != E_SUCCESS) return __r; }
#define _N(x, mr_ctx, ctx) { int __r = x; if(__r != E_SUCCESS) { ctx->next(__r, ctx, mr_ctx); return; } }
#define _E(x, mr_ctx, ctx) { int __r = x; if(__r != E_SUCCESS) { (mr_ctx->next = ctx->next)(__r, ctx, mr_ctx); return; } }

	typedef struct {
		mr_config* config;
		mr_sha_ctx sha_ctx;
	} _mr_ctx;

	typedef struct {
		mr_aes_ctx aes_ctx;
		unsigned char ctr[16];
	} _mr_aesctr_ctx;

	int kdf_compute(mr_ctx mr_ctx, const unsigned char* key, unsigned int keylen, const unsigned char* info, unsigned int infolen, unsigned char* output, unsigned int spaceavail);

	int aesctr_init(_mr_aesctr_ctx *ctx, mr_aes_ctx aes, const unsigned char *iv, unsigned int ivsize);
	int aesctr_process(_mr_aesctr_ctx *ctx, const unsigned char* data, unsigned int amount, unsigned char* output, unsigned int spaceavail);
#ifdef __cplusplus
}
#endif