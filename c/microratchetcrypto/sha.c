#include "pch.h"
#include <microratchet.h>


static const uint32_t sh256initstate[8] = {
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19
};

static const uint32_t k[] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define sha_ror(bits, wut) ((uint32_t)(((wut) & 0xffffffff) >> (bits)) | (uint32_t)((wut) << (32 - bits)))
#define sha_s0a(x) (sha_ror(7, x) ^ sha_ror(18, x) ^  (x >> 3))
#define sha_s1a(x) (sha_ror(17, x) ^ sha_ror(19, x) ^  (x >> 10))
#define sha_s0b(x) (sha_ror(2, x) ^ sha_ror(13, x) ^  sha_ror(22, x))
#define sha_s1b(x) (sha_ror(6, x) ^ sha_ror(11, x) ^  sha_ror(25, x))

typedef struct {
	mr_ctx mr_ctx;
	uint32_t total;
	uint32_t state[8];
	uint8_t buffer[64];
} _mr_sha_ctx;

mr_sha_ctx mr_sha_create(mr_ctx mr_ctx)
{
	_mr_sha_ctx* ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_sha_ctx), (void**)&ctx);
	if (r != MR_E_SUCCESS) return 0;

	memset(ctx, 0, sizeof(_mr_sha_ctx));
	ctx->mr_ctx = mr_ctx;

	return ctx;
}

mr_result mr_sha_init(mr_sha_ctx _ctx)
{
	FAILIF(!_ctx, MR_E_INVALIDARG, "ctx must be specified");
	_mr_sha_ctx* ctx = (_mr_sha_ctx*)_ctx;

	ctx->total = 0;
	memcpy(ctx->state, sh256initstate, sizeof(ctx->state));

	return MR_E_SUCCESS;
}

static void sha_process_internal(uint32_t state[8], const uint8_t block[64])
{
	// working schedule
	uint32_t w[64];
	// working variables (a-h in spec)
	uint32_t t[8];
	uint32_t *d = (uint32_t*)block;

	// make sure input is aligned
	MR_ASSERT(((size_t)d % 4) == 0);

	// copy state into stack
	for (uint32_t i = 0; i < 8; i++)
	{
		t[i] = state[i];
	}

	// compression step
	for (uint32_t i = 0; i < 64; i++)
	{
		if (i < 16)
		{
			// copy block into schedule
			w[i] = MR_HTON(d[i]);
		}
		else
		{
			// distribute block into scheudle
			w[i] = w[i - 16] + sha_s0a(w[i - 15]) + w[i - 7] + sha_s1a(w[i - 2]);
		}

		uint32_t temp1 = t[7] + sha_s1b(t[4]) +
			((t[4] & t[5]) ^ ((~t[4]) & t[6])) +
			k[i] + w[i];
		uint32_t temp2 = sha_s0b(t[0]) +
			((t[0] & t[1]) ^ (t[0] & t[2]) ^ (t[1] & t[2]));
		t[7] = t[6];
		t[6] = t[5];
		t[5] = t[4];
		t[4] = t[3] + temp1;
		t[3] = t[2];
		t[2] = t[1];
		t[1] = t[0];
		t[0] = temp1 + temp2;
	}

	// add working values onto state
	for (uint32_t i = 0; i < 8; i++)
	{
		state[i] += t[i];
	}
}

mr_result mr_sha_process(mr_sha_ctx _ctx, const uint8_t* data, uint32_t howmuch)
{
	FAILIF(!_ctx || !data, MR_E_INVALIDARG, "!ctx || !data");
	FAILIF(!howmuch, MR_E_SUCCESS, "!howmuch");
	_mr_sha_ctx* ctx = (_mr_sha_ctx*)_ctx;

	uint8_t* buffer = ctx->buffer;
	uint32_t blockpart = ctx->total % 64;

	// process leftover partial block from previous run if
	// it hasn't been digested yet.
	if (blockpart > 0)
	{
		uint32_t blockremain = 64 - blockpart;
		uint32_t copyamount = blockremain > howmuch ? blockremain : howmuch;
		memcpy(buffer + blockpart, data, copyamount);
		blockpart += copyamount;
		blockremain -= copyamount;
		data += copyamount;
		howmuch -= copyamount;
		ctx->total += copyamount;
		if (blockpart == 64)
		{
			sha_process_internal(ctx->state, ctx->buffer);
		}
	}

	// process data in 64 byte blocks
	while (howmuch >= 64)
	{
		sha_process_internal(ctx->state, data);
		data += 64;
		howmuch -= 64;
		ctx->total += 64;
	}

	// buffer the remaining stuff
	if (howmuch > 0)
	{
		memcpy(buffer, data, howmuch);
		ctx->total += howmuch;
	}

	return MR_E_SUCCESS;
}

mr_result mr_sha_compute(mr_sha_ctx _ctx, uint8_t* output, uint32_t spaceavail)
{
	FAILIF(!_ctx || !output, MR_E_INVALIDARG, "!ctx || !output");
	FAILIF(spaceavail < 32, MR_E_INVALIDSIZE, "spaceavail < 32");
	_mr_sha_ctx* ctx = (_mr_sha_ctx*)_ctx;

	uint8_t* buffer = ctx->buffer;
	uint32_t blockpart = ctx->total % 64;
	uint32_t blockremain = 64 - blockpart;

	// padding is 1 bit then 0's until end except for length
	buffer[blockpart] = 0x80;
	blockremain--;
	blockpart++;

	// if there is not enough space for padding we need
	// to process another block
	if (blockremain < 4)
	{
		// pad out the buffer
		do
		{
			buffer[blockpart++] = 0;
		} while (--blockremain > 0);

		sha_process_internal(ctx->state, ctx->buffer);
		blockpart = 0;
		memset(buffer, 0, 60);
	}
	else
	{
		memset(buffer + blockpart, 0, blockremain - 4);
	}

	// put length at the end as big endian number
	uint32_t total = ctx->total * 8;
	total = MR_HTON(total);
	// we assume 32 bit aligned allocations
	MR_ASSERT(((size_t)buffer % 4) == 0);
	*(uint32_t*)(buffer + 60) = total;

	// process the final block
	sha_process_internal(ctx->state, ctx->buffer);

	// copy out the state
	uint32_t* out = (uint32_t*)output;
	MR_ASSERT(((size_t)out % 4) == 0);
	out[0] = MR_HTON(ctx->state[0]);
	out[1] = MR_HTON(ctx->state[1]);
	out[2] = MR_HTON(ctx->state[2]);
	out[3] = MR_HTON(ctx->state[3]);
	out[4] = MR_HTON(ctx->state[4]);
	out[5] = MR_HTON(ctx->state[5]);
	out[6] = MR_HTON(ctx->state[6]);
	out[7] = MR_HTON(ctx->state[7]);

	return MR_E_SUCCESS;
}

void mr_sha_destroy(mr_sha_ctx ctx)
{
	if (ctx)
	{
		_mr_sha_ctx* _ctx = (_mr_sha_ctx*)ctx;
		mr_ctx mrctx = _ctx->mr_ctx;
		memset(_ctx, 0, sizeof(_mr_sha_ctx));
		mr_free(mrctx, _ctx);
	}
}
