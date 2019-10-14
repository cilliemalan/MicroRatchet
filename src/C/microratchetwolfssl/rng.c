#include "pch.h"
#include <microratchet.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef CUSTOM_RNG
extern const uint8_t* random_data;
extern const uint32_t random_data_length;
#endif

typedef struct {
	mr_ctx mr_ctx;
	WC_RNG rng;
#ifdef CUSTOM_RNG
	const uint8_t* random_data;
	uint32_t random_data_length;
	uint32_t random_data_index;
#endif
} _mr_rng_ctx;


#ifdef CUSTOM_RNG
mr_rng_ctx mr_rng_create_custom(mr_ctx mr_ctx, const uint8_t* random_data, uint32_t random_data_length, uint32_t random_data_index)
{
	_mr_rng_ctx* rng = (_mr_rng_ctx*)mr_rng_create(mr_ctx);
	rng->random_data = random_data;
	rng->random_data_length = random_data_length;
	rng->random_data_index = random_data_index;
	return rng;
}
#endif

mr_rng_ctx mr_rng_create(mr_ctx mr_ctx)
{
	_mr_rng_ctx* ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_rng_ctx), &ctx);
	if (r != E_SUCCESS) return 0;

	*ctx = (_mr_rng_ctx){ mr_ctx };
	return ctx;
}

mr_result_t mr_rng_generate(mr_rng_ctx _ctx, uint8_t* output, uint32_t outputsize)
{
	_mr_rng_ctx* ctx = _ctx;
	FAILIF(outputsize < 1, E_INVALIDSIZE, "outputsize < 1")
	FAILIF(!output, E_INVALIDARGUMENT, "!output")

#ifdef CUSTOM_RNG
	if (ctx->random_data && ctx->random_data_length)
	{
		uint32_t amt = outputsize;
		uint8_t* ptr = output;
		while (amt > 0)
		{
			uint32_t cpy = min(amt, ctx->random_data_length - ctx->random_data_index);
			memcpy(output, ctx->random_data + ctx->random_data_index, cpy);
			amt -= cpy;
			ptr += cpy;
			ctx->random_data_index = (ctx->random_data_index + cpy) % ctx->random_data_length;
		}

		return E_SUCCESS;
	}
#endif

	if (ctx->rng.seed.handle == 0)
	{
		int r = wc_InitRng(&ctx->rng);
		FAILIF(r != 0, E_INVALIDOP, "r != 0")
	}

	int r = wc_RNG_GenerateBlock(&ctx->rng, output, outputsize);
	FAILIF(r != 0, E_INVALIDOP, "r != 0")
	return E_SUCCESS;
}

void mr_rng_destroy(mr_rng_ctx _ctx)
{
	if (_ctx)
	{
		_mr_rng_ctx* ctx = _ctx;
		wc_FreeRng(&ctx->rng);
		*ctx = (_mr_rng_ctx){ 0 };
		mr_free(ctx->mr_ctx, ctx);
	}
}
