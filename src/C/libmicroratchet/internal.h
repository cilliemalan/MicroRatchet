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
		unsigned char ipad[64];
		unsigned char opad[64];
		unsigned char output[32];
		unsigned char* data;
		unsigned int datalen;
	} _hmac_ctx;




	int hmac_init(_hmac_ctx *hmac, mr_ctx mr_ctx, const unsigned char* key, unsigned int keylen);
	int hmac_process(_hmac_ctx *hmac, mr_ctx mr_ctx, const unsigned char* data, unsigned int datalen);
	int hmac_compute(_hmac_ctx *hmac, mr_ctx mr_ctx, unsigned char* output, unsigned int spaceavail);


#ifdef __cplusplus
}
#endif