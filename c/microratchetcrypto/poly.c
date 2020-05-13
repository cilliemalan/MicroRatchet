#include "pch.h"
#include <microratchet.h>

typedef struct {
	uint32_t r[4];
	uint32_t n[4];
	uint8_t d[16];
	uint32_t h[5];
	uint32_t num;
	mr_ctx mr_ctx;
} _mr_poly_ctx;

# define CONSTANT_TIME_CARRY(a,b) ( \
         (a ^ ((a ^ b) | ((a - b) ^ b))) >> (sizeof(a) * 8 - 1) \
         )


static void poly1305_init(_mr_poly_ctx* ctx, const uint8_t key[32])
{
	const uint32_t* ukey = (const uint32_t*)key;
	ctx->r[0] = ukey[0] & 0x0fffffff;
	ctx->r[1] = ukey[1] & 0x0ffffffc;
	ctx->r[2] = ukey[2] & 0x0ffffffc;
	ctx->r[3] = ukey[3] & 0x0ffffffc;
	ctx->n[0] = ukey[4];
	ctx->n[1] = ukey[5];
	ctx->n[2] = ukey[6];
	ctx->n[3] = ukey[7];
	memset(ctx->d, 0, sizeof(ctx->d));
	ctx->h[0] = 0;
	ctx->h[1] = 0;
	ctx->h[2] = 0;
	ctx->h[3] = 0;
	ctx->h[4] = 0;
	ctx->num = 0;
}

static void poly1305_update_internal(_mr_poly_ctx* ctx, const uint8_t* data, uint32_t len, bool pad)
{
	uint32_t* du = (uint32_t*)data;

	// copy state into the stack
	uint32_t r[4];
	r[0] = ctx->r[0];
	r[1] = ctx->r[1];
	r[2] = ctx->r[2];
	r[3] = ctx->r[3];
	uint32_t h[5];
	h[0] = ctx->h[0];
	h[1] = ctx->h[1];
	h[2] = ctx->h[2];
	h[3] = ctx->h[3];
	h[4] = ctx->h[4];

	uint32_t s[3];
	s[0] = r[1] + (r[1] >> 2);
	s[1] = r[2] + (r[2] >> 2);
	s[2] = r[3] + (r[3] >> 2);

	for (uint32_t i = 0; i < len / 16; i++)
	{
		// add d to h
		uint64_t d[4];
		d[0] = (uint64_t)h[0] + du[i + 0];
		d[1] = (uint64_t)h[1] + du[i + 1] + (d[0] >> 32);
		d[2] = (uint64_t)h[2] + du[i + 2] + (d[1] >> 32);
		d[3] = (uint64_t)h[3] + du[i + 3] + (d[2] >> 32);
		h[0] = (uint32_t)d[0];
		h[1] = (uint32_t)d[1];
		h[2] = (uint32_t)d[2];
		h[3] = (uint32_t)d[3];
		h[4] += (d[3] >> 32) + !!pad;

		// do multiply thing
		d[0] = ((uint64_t)h[0] * r[0]) +
			((uint64_t)h[1] * s[2]) +
			((uint64_t)h[2] * s[1]) +
			((uint64_t)h[3] * s[0]);
		d[1] = ((uint64_t)h[0] * r[1]) +
			((uint64_t)h[1] * r[0]) +
			((uint64_t)h[2] * s[2]) +
			((uint64_t)h[3] * s[1]) +
			((uint64_t)h[4] * s[0]);
		d[2] = ((uint64_t)h[0] * r[2]) +
			((uint64_t)h[1] * r[1]) +
			((uint64_t)h[2] * r[0]) +
			((uint64_t)h[3] * s[2]) +
			((uint64_t)h[4] * s[1]);
		d[3] = ((uint64_t)h[0] * r[3]) +
			((uint64_t)h[1] * r[2]) +
			((uint64_t)h[2] * r[1]) +
			((uint64_t)h[3] * s[0]) +
			((uint64_t)h[4] * s[2]);
		h[4] *= r[0];

		// reduce
		d[1] += d[0] >> 32;
		d[2] += d[1] >> 32;
		d[3] += d[2] >> 32;
		h[0] = (uint32_t)d[0];
		h[1] = (uint32_t)d[1];
		h[2] = (uint32_t)d[2];
		h[3] = (uint32_t)d[3];
		h[4] += (uint32_t)(d[3] >> 32);

		// carry thing
		uint32_t c = (h[4] >> 2) + (h[4] & 0xfffffffc);
		h[4] &= 3;
		h[0] += c;
		(c = CONSTANT_TIME_CARRY(h[0], c));
		h[1] += c;
		(c = CONSTANT_TIME_CARRY(h[1], c));
		h[2] += c;
		(c = CONSTANT_TIME_CARRY(h[2], c));
		h[3] += c;
		c = CONSTANT_TIME_CARRY(h[3], c);
		h[4] += c;
	}

	// update state
	ctx->h[0] = h[0];
	ctx->h[1] = h[1];
	ctx->h[2] = h[2];
	ctx->h[3] = h[3];
	ctx->h[4] = h[4];
}

static void poly1305_final_internal(_mr_poly_ctx* ctx, uint8_t mac[16])
{
	// copy stuff into stack
	uint32_t h[5];
	h[0] = ctx->h[0];
	h[1] = ctx->h[1];
	h[2] = ctx->h[2];
	h[3] = ctx->h[3];
	h[4] = ctx->h[4];
	uint32_t n[4];
	n[0] = ctx->n[0];
	n[1] = ctx->n[1];
	n[2] = ctx->n[2];
	n[3] = ctx->n[3];

	// subtract
	uint32_t g[5];
	uint64_t t = (uint64_t)h[0] + 5;
	g[0] = (uint32_t)t;
	t = (uint64_t)h[1] + (t >> 32);
	g[1] = (uint32_t)t;
	t = (uint64_t)h[2] + (t >> 32);
	g[2] = (uint32_t)t;
	t = (uint64_t)h[3] + (t >> 32);
	g[3] = (uint32_t)t;
	g[4] = h[4] + (uint32_t)(t >> 32);

	// do the carry thing
	uint32_t m = 0 - (g[4] >> 2);
	g[0] &= m;
	g[1] &= m;
	g[2] &= m;
	g[3] &= m;
	m = ~m;
	h[0] = (h[0] & m) | g[0];
	h[1] = (h[1] & m) | g[1];
	h[2] = (h[2] & m) | g[2];
	h[3] = (h[3] & m) | g[3];

	// add nonce and subtract again
	t = (uint64_t)h[0] + n[0];
	h[0] = (uint32_t)t;
	t = (uint64_t)h[1] + (t >> 32) + n[1];
	h[1] = (uint32_t)t;
	t = (uint64_t)h[2] + (t >> 32) + n[2];
	h[2] = (uint32_t)t;
	t = (uint64_t)h[3] + (t >> 32) + n[3];
	h[3] = (uint32_t)t;

	// copy out
	uint32_t* um = (uint32_t*)mac;
	um[0] = h[0];
	um[1] = h[1];
	um[2] = h[2];
	um[3] = h[3];
}

static void poly1305_update(_mr_poly_ctx* ctx, const uint8_t* data, uint32_t len)
{
	// process unaligned remainder
	uint32_t num = ctx->num;
	if (num)
	{
		uint32_t rest = 16 - num;
		if (len >= num)
		{
			memcpy(ctx->d + num, data, rest);
			poly1305_update_internal(ctx, ctx->d, 16, true);
			data += rest;
			len -= rest;
			ctx->num = 0;
		}
		else
		{
			memcpy(ctx->d, data, len);
			ctx->num += rest;
			return;
		}
	}

	// quantize length to 16 bytes
	uint32_t toprocess = len / 16 * 16;
	if (toprocess)
	{
		poly1305_update_internal(ctx, data, toprocess, true);
		data += toprocess;
		len -= toprocess;
	}

	// put leftovers in buffer
	if (len > 0)
	{
		memcpy(ctx->d, data, len);
		ctx->num = len;
	}
}

static void poly1305_final(_mr_poly_ctx* ctx, uint8_t mac[16])
{
	uint32_t num = ctx->num;
	if (num)
	{
		// pad out the buffer
		ctx->d[num] = 1;
		for (uint32_t i = num + 1; i < 16; i++)
		{
			ctx->d[i] = 0;
		}

		poly1305_update_internal(ctx, ctx->d, 16, false);
	}

	poly1305_final_internal(ctx, mac);
}

mr_poly_ctx mr_poly_create(mr_ctx mr_ctx)
{
	_mr_poly_ctx* ctx;
	mr_result r = mr_allocate(mr_ctx, sizeof(_mr_poly_ctx), (void**)&ctx);
	if (r != MR_E_SUCCESS) return 0;

    memset(ctx, 0, sizeof(_mr_poly_ctx));
    ctx->mr_ctx = mr_ctx;

	return ctx;
}

mr_result mr_poly_init(mr_poly_ctx _ctx, const uint8_t* key, uint32_t keysize, const uint8_t* iv, uint32_t ivsize)
{
	_mr_poly_ctx* ctx = _ctx;
	FAILIF(keysize != 32, MR_E_INVALIDSIZE, "keysize != 32");
	FAILIF(ivsize != 16, MR_E_INVALIDSIZE, "ivsize != 16");
	FAILIF(!key || !_ctx || !iv, MR_E_INVALIDARG, "!key || !_ctx || !iv");

	mr_result result = MR_E_SUCCESS;
	uint8_t tkey[32];
	memcpy(tkey, key, 16);

	mr_aes_ctx aes = mr_aes_create(ctx->mr_ctx);
	if (!aes)
	{
		result = MR_E_NOMEM;
	}
	_R(result, mr_aes_init(aes, key + 16, 16));
	_R(result, mr_aes_process(aes, iv, 16, tkey + 16, 16));
	mr_aes_destroy(aes);
	if (result == MR_E_SUCCESS)
	{
		poly1305_init(ctx, tkey);
	}

	return result;
}

mr_result mr_poly_process(mr_poly_ctx _ctx, const uint8_t* data, uint32_t amount)
{
	_mr_poly_ctx* ctx = _ctx;
	FAILIF(!amount, MR_E_INVALIDSIZE, "!amount");
	FAILIF(!data || !_ctx, MR_E_INVALIDARG, "!data || !_ctx");

	poly1305_update(ctx, data, amount);

	return MR_E_SUCCESS;
}

mr_result mr_poly_compute(mr_poly_ctx _ctx, uint8_t* output, uint32_t spaceavail)
{
	_mr_poly_ctx* ctx = _ctx;
	FAILIF(!spaceavail, MR_E_INVALIDSIZE, "!spaceavail");
	FAILIF(!output || !_ctx, MR_E_INVALIDARG, "!output || !_ctx");

	uint8_t o[16];
	poly1305_final(ctx, o);
	memcpy(output, o, spaceavail < 16 ? spaceavail : 16);

	// reset
	memset(ctx->d, 0, sizeof(ctx->d));
	ctx->h[0] = 0;
	ctx->h[1] = 0;
	ctx->h[2] = 0;
	ctx->h[3] = 0;
	ctx->h[4] = 0;

	return MR_E_SUCCESS;
}

void mr_poly_destroy(mr_poly_ctx ctx)
{
	if (ctx)
	{
		_mr_poly_ctx* _ctx = (_mr_poly_ctx*)ctx;
        mr_ctx mrctx = _ctx->mr_ctx;
		memset(_ctx , 0, sizeof(_mr_poly_ctx));
		mr_free(mrctx, _ctx);
	}
}
