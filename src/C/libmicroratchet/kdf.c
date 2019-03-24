#include "pch.h"
#include "microratchet.h"
#include "internal.h"

static int hmac_after_process_digest(_hmac_ctx* ctx, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx);
static int hmac_after_compute_first_compute(_hmac_ctx* ctx, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx);
static int hmac_after_compute_first_process(_hmac_ctx* ctx, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx);
static int hmac_after_compute_second_compute(_hmac_ctx* ctx, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx);
static int hmac_after_compute_second_process(_hmac_ctx* ctx, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx);

// init
int hmac_init(_hmac_ctx *ctx, mr_ctx mr_ctx_, const unsigned char* key, unsigned int keylen)
{
	_mr_ctx* mr_ctx = mr_ctx_;

	_C(mr_sha_init(mr_ctx->sha_ctx));

	if (keylen > 64)
	{
		_C(mr_sha_process(mr_ctx->sha_ctx, key, keylen));
		memset(ctx->ipad + 32, 0, 32);
		_C(mr_sha_compute(mr_ctx->sha_ctx, ctx->ipad, 64));
	}
	else
	{
		int iremain = 64 - keylen;
		int oremain = 96 - keylen;
		if (iremain > 0) memset(ctx->ipad + keylen, 0, iremain);
		memcpy(ctx->ipad, key, keylen);
	}

	memcpy(ctx->opad, ctx->ipad, 64);

	for (int i = 0; i < 64; i++) ctx->ipad[i] ^= 0x36;
	for (int i = 0; i < 64; i++) ctx->opad[i] ^= 0x5C;

	_C(mr_sha_process(mr_ctx->sha_ctx, ctx->ipad, 64));
	return E_SUCCESS;
}

// process
int hmac_process(_hmac_ctx *ctx, mr_ctx mr_ctx_, const unsigned char* data, unsigned int datalen)
{
	_mr_ctx* mr_ctx = mr_ctx_;
	_C(mr_sha_process(mr_ctx->sha_ctx, data, datalen));
	return E_SUCCESS;
}

// compute
int hmac_compute(_hmac_ctx *ctx, mr_ctx mr_ctx_, unsigned char* output, unsigned int spaceavail)
{
	_mr_ctx* mr_ctx = mr_ctx_;
	if (!output) return E_INVALIDARGUMENT;
	if (spaceavail != 32) return E_INVALIDSIZE;

	{
		unsigned char tmp[32];
		_C(mr_sha_compute(mr_ctx->sha_ctx, tmp, 32));
		_C(mr_sha_process(mr_ctx->sha_ctx, ctx->opad, 64));
		_C(mr_sha_process(mr_ctx->sha_ctx, tmp, 32));
	}
	_C(mr_sha_compute(mr_ctx->sha_ctx, output, spaceavail));
	_C(mr_sha_process(mr_ctx->sha_ctx, ctx->ipad, 64));
	return E_SUCCESS;
}