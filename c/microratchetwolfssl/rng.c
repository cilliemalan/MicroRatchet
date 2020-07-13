#include "pch.h"
#include <microratchet.h>
#include <wolfssl/wolfcrypt/random.h>


#ifdef __GNUC__
static inline int _rdseed64_step(uint64_t* seed)
{
	unsigned char ok;
	__asm__ volatile("rdseed %0; setc %1":"=r"(*seed), "=qm"(ok));
	return (ok) ? 0 : -1;
}
#endif


typedef struct
{
	mr_ctx mr_ctx;
	WC_RNG rng;
} _mr_rng_ctx;

// hack for os specific seeder
#if defined(USE_WINDOWS_API) || defined(WIN32) || defined(_WIN32) || defined(_WIN64)
#define RNGSEEDHANDLEFIELD handle
#else
#define RNGSEEDHANDLEFIELD fd
#endif

mr_rng_ctx mr_rng_create(mr_ctx mr_ctx)
{
	_mr_rng_ctx *ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_rng_ctx), (void **)&ctx);
	if (r != MR_E_SUCCESS)
		return 0;

    mr_memzero(ctx, sizeof(_mr_rng_ctx));
    ctx->mr_ctx = mr_ctx;

	return ctx;
}

mr_result mr_rng_generate(mr_rng_ctx _ctx, uint8_t *output, uint32_t outputsize)
{
	_mr_rng_ctx *ctx = _ctx;
	FAILIF(outputsize < 1, MR_E_INVALIDSIZE, "outputsize < 1");
	FAILIF(!output, MR_E_INVALIDARG, "!output");

	if (ctx->rng.seed.RNGSEEDHANDLEFIELD == 0)
	{
		int r = wc_InitRng(&ctx->rng);
		FAILIF(r != 0, MR_E_INVALIDOP, "r != 0");
	}

	int r = wc_RNG_GenerateBlock(&ctx->rng, output, outputsize);
	FAILIF(r != 0, MR_E_INVALIDOP, "r != 0");
	return MR_E_SUCCESS;
}

void mr_rng_destroy(mr_rng_ctx _ctx)
{
	if (_ctx)
	{
		_mr_rng_ctx *ctx = _ctx;
		wc_FreeRng(&ctx->rng);
		mr_ctx mrctx = ctx->mr_ctx;
		mr_memzero(ctx , sizeof(_mr_rng_ctx));
		mr_free(mrctx, ctx);
	}
}

int CUSTOM_RAND_GENERATE_SEED_OS(void* os, uint8_t *output, uint32_t sz)
{
	return mr_rng_seed(output, sz);
}