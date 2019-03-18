#include "pch.h"
#include "microratchet.h"
#include "internal.h"

static void hmac_after_init_smallkey(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx);
static void hmac_after_init_largekey(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx);
static void hmac_after_init_key_process(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx);
static void hmac_after_init_key_compute(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx);
static void hmac_after_init_first_process(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx);
static void hmac_after_process_digest(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx);
static void hmac_after_compute_first_compute(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx);
static void hmac_after_compute_first_process(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx);
static void hmac_after_compute_second_compute(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx);
static void hmac_after_compute_second_process(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx);

// init
int hmac_init(_hmac_ctx *ctx, mr_ctx mr_ctx_, const unsigned char* key, unsigned int keylen)
{
	_mr_ctx* mr_ctx = mr_ctx_;
	mr_ctx->user = ctx;

	ctx->data = (unsigned char*)key;
	ctx->datalen = keylen;
	ctx->next = mr_ctx->next;

	if (keylen > 64)
	{
		mr_ctx->next = hmac_after_init_largekey;
	}
	else
	{
		mr_ctx->next = hmac_after_init_smallkey;
	}

	_C(mr_sha_init(mr_ctx->sha_ctx));

	return E_SUCCESS;
}

static void hmac_after_init_smallkey(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx)
{
	_hmac_ctx* ctx = mr_ctx->user;
	if (status != E_SUCCESS) { mr_ctx->next = ctx->next; hmac_init_cb(status, ctx, mr_ctx); return; }

	const unsigned char* key = ctx->data;
	unsigned int keylen = ctx->datalen;
	int iremain = 64 - keylen;
	int oremain = 96 - keylen;
	if (iremain > 0) memset(ctx->ipad + keylen, 0, iremain);
	memcpy(ctx->ipad, key, keylen);

	hmac_after_init_key_compute(E_SUCCESS, sha_ctx, mr_ctx);
}

static void hmac_after_init_largekey(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx)
{
	_hmac_ctx* ctx = mr_ctx->user;
	if (status != E_SUCCESS) { mr_ctx->next = ctx->next; hmac_init_cb(status, ctx, mr_ctx); return; }

	const unsigned char* key = ctx->data;
	unsigned int keylen = ctx->datalen;

	mr_ctx->next = hmac_after_init_key_process;
	status = mr_sha_process(sha_ctx, key, keylen);
	if (status != E_SUCCESS) { mr_ctx->next = ctx->next; hmac_init_cb(status, ctx, mr_ctx); return; }

	mr_ctx->next = hmac_after_init_key_process;
}

static void hmac_after_init_key_process(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx)
{
	_hmac_ctx* ctx = mr_ctx->user;
	if (status != E_SUCCESS) { mr_ctx->next = ctx->next; hmac_init_cb(status, ctx, mr_ctx); return; }

	memset(ctx->ipad + 32, 0, 32);

	mr_ctx->next = hmac_after_init_key_compute;
	status = mr_sha_compute(sha_ctx, ctx->ipad, 64);
	if (status != E_SUCCESS) { mr_ctx->next = ctx->next; hmac_init_cb(status, ctx, mr_ctx); return; }
}

static void hmac_after_init_key_compute(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx)
{
	_hmac_ctx* ctx = mr_ctx->user;
	if (status != E_SUCCESS) { mr_ctx->next = ctx->next; hmac_init_cb(status, ctx, mr_ctx); return; }

	memcpy(ctx->opad, ctx->ipad, 64);

	for (int i = 0; i < 64; i++) ctx->ipad[i] ^= 0x36;
	for (int i = 0; i < 64; i++) ctx->opad[i] ^= 0x5C;

	mr_ctx->next = hmac_after_init_first_process;
	status = mr_sha_process(sha_ctx, ctx->ipad, 64);
	if (status != E_SUCCESS) { mr_ctx->next = ctx->next; hmac_init_cb(status, ctx, mr_ctx); return; }
}

static void hmac_after_init_first_process(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx)
{
	_hmac_ctx* ctx = mr_ctx->user;
	if (status != E_SUCCESS) { mr_ctx->next = ctx->next; hmac_init_cb(status, ctx, mr_ctx); return; }

	mr_ctx->next = ctx->next;
	hmac_init_cb(E_SUCCESS, ctx, mr_ctx);
}

// process
int hmac_process(_hmac_ctx *ctx, mr_ctx mr_ctx_, const unsigned char* data, unsigned int datalen)
{
	_mr_ctx* mr_ctx = mr_ctx_;
	mr_ctx->user = ctx;
	ctx->next = mr_ctx->next;
	mr_ctx->next = hmac_after_process_digest;
	_C(mr_sha_process(mr_ctx->sha_ctx, data, datalen));

	return E_SUCCESS;
}

static void hmac_after_process_digest(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx)
{
	_hmac_ctx* ctx = mr_ctx->user;
	if (status != E_SUCCESS) { mr_ctx->next = ctx->next; hmac_init_cb(status, ctx, mr_ctx); return; }

	mr_ctx->next = ctx->next;
	hmac_process_cb(E_SUCCESS, ctx, mr_ctx);
}

// compute
int hmac_compute(_hmac_ctx *ctx, mr_ctx mr_ctx_, unsigned char* output, unsigned int spaceavail)
{
	_mr_ctx* mr_ctx = mr_ctx_;
	if (!output) return E_INVALIDARGUMENT;
	if (spaceavail != 32) return E_INVALIDSIZE;

	ctx->data = output;
	ctx->datalen = spaceavail;

	mr_ctx->user = ctx;
	ctx->next = mr_ctx->next;
	mr_ctx->next = hmac_after_compute_first_compute;
	mr_sha_compute(mr_ctx->sha_ctx, ctx->output, sizeof(ctx->output));

	return E_SUCCESS;
}

static void hmac_after_compute_first_compute(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx)
{
	_hmac_ctx* ctx = mr_ctx->user;
	if (status != E_SUCCESS) { mr_ctx->next = ctx->next; hmac_init_cb(status, ctx, mr_ctx); return; }

	mr_ctx->next = hmac_after_compute_first_process;
	status = mr_sha_process(sha_ctx, ctx->opad, 96);
	if (status != E_SUCCESS) { mr_ctx->next = ctx->next; hmac_init_cb(status, ctx, mr_ctx); return; }
}

static void hmac_after_compute_first_process(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx)
{
	_hmac_ctx* ctx = mr_ctx->user;
	if (status != E_SUCCESS) { mr_ctx->next = ctx->next; hmac_init_cb(status, ctx, mr_ctx); return; }

	mr_ctx->next = hmac_after_compute_second_compute;
	status = mr_sha_compute(sha_ctx, ctx->data, ctx->datalen);
	if (status != E_SUCCESS) { mr_ctx->next = ctx->next; hmac_init_cb(status, ctx, mr_ctx); return; }
}

static void hmac_after_compute_second_compute(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx)
{
	_hmac_ctx* ctx = mr_ctx->user;
	if (status != E_SUCCESS) { mr_ctx->next = ctx->next; hmac_init_cb(status, ctx, mr_ctx); return; }

	mr_ctx->next = hmac_after_compute_second_process;
	status = mr_sha_process(sha_ctx, ctx->ipad, 64);
	if (status != E_SUCCESS) { mr_ctx->next = ctx->next; hmac_init_cb(status, ctx, mr_ctx); return; }
}

static void hmac_after_compute_second_process(int status, mr_sha_ctx sha_ctx, _mr_ctx *mr_ctx)
{
	_hmac_ctx* ctx = mr_ctx->user;
	if (status != E_SUCCESS) { mr_ctx->next = ctx->next; hmac_init_cb(status, ctx, mr_ctx); return; }

	mr_ctx->next = ctx->next;
	hmac_compute_cb(E_SUCCESS, ctx, mr_ctx);
}
