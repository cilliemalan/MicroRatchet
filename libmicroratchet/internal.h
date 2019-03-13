#pragma once

#ifdef __cplusplus
extern "C" {
#endif


#define _C(x) { int __r = x; if(__r != E_SUCCESS) return __r; }
#define _N(x, mr_ctx, ctx) { int __r = x; if(__r != E_SUCCESS) { ctx->next(__r, ctx, mr_ctx); return; } }
#define _E(x, mr_ctx, ctx) { int __r = x; if(__r != E_SUCCESS) { (mr_ctx->next = ctx->next)(__r, ctx, mr_ctx); return; } }

typedef struct {
	mr_config* config;
	void* user;
	mr_sha_ctx sha_ctx;
	void(*next)(int status, mr_ctx mr_ctx, void* ctx);
} _mr_ctx;


typedef struct {
	unsigned char ipad[64];
	unsigned char opad[64];
	unsigned char output[32];
	unsigned char* data;
	unsigned int datalen;
	void(*next)(int status, mr_ctx mr_ctx, void* ctx);
} _hmac_ctx;




int hmac_init(_mr_ctx *mr_ctx, _hmac_ctx *hmac, const unsigned char* key, unsigned int keylen);
void hmac_init_cb(int status, _hmac_ctx* ctx, mr_ctx mr_ctx);
int hmac_process(_mr_ctx *mr_ctx, _hmac_ctx *hmac, const unsigned char* data, unsigned int datalen);
void hmac_process_cb(int status, _hmac_ctx* ctx, mr_ctx mr_ctx);
int hmac_compute(_mr_ctx *mr_ctx, _hmac_ctx *hmac, unsigned char* output, unsigned int spaceavail);
void hmac_compute_cb(int status, _hmac_ctx* ctx, mr_ctx mr_ctx);

#ifdef __cplusplus
}
#endif