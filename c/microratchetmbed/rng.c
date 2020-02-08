#include "pch.h"
#include <microratchet.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

typedef struct
{
	mr_ctx mr_ctx;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
} _mr_rng_ctx;

mr_rng_ctx mr_rng_create(mr_ctx mr_ctx)
{
	_mr_rng_ctx* ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_rng_ctx), (void**)&ctx);
	if (r != MR_E_SUCCESS)
		return 0;

	ctx->mr_ctx = mr_ctx;
	mbedtls_entropy_init(&ctx->entropy);
	mbedtls_ctr_drbg_init(&ctx->ctr_drbg);

	int ret = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy, 0, 0);
	if (ret != 0)
	{
		mr_free(mr_ctx, ctx);
		FAILIF(ret, 0, "Failed to initialize RNG");
	}

	return ctx;
}

mr_result mr_rng_generate(mr_rng_ctx _ctx, uint8_t* output, uint32_t outputsize)
{
	_mr_rng_ctx* ctx = _ctx;
	FAILIF(outputsize < 1, MR_E_INVALIDSIZE, "outputsize < 1");
	FAILIF(!output, MR_E_INVALIDARG, "!output");

	int r = mbedtls_ctr_drbg_random(&ctx->ctr_drbg, output, outputsize);
	FAILIF(r, MR_E_INVALIDOP, "Failed to generate random numbers");

	return MR_E_SUCCESS;
}

void mr_rng_destroy(mr_rng_ctx _ctx)
{
	if (_ctx)
	{
		_mr_rng_ctx* ctx = _ctx;
		mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
		mbedtls_entropy_free(&ctx->entropy);
		mr_free(ctx->mr_ctx, ctx);
	}
}
