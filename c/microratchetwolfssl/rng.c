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

    memset(ctx, 0, sizeof(_mr_rng_ctx));
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
		memset(ctx , 0, sizeof(_mr_rng_ctx));
		mr_free(ctx->mr_ctx, ctx);
	}
}




#ifdef HAVE_INTEL_RDSEED
#include <immintrin.h>


static inline int IntelRDseed64_r(word64* rnd)
{
    for (int i = 0; i < 128; i++)
	{
		unsigned char ok = _rdseed64_step(rnd);
        if (ok == 1) return MR_E_SUCCESS;
    }
    return MR_E_RNGFAIL;
}

#endif


// we might need to make up our own random seed
WEAK_SYMBOL int mr_rng_seed(uint8_t *output, uint32_t sz)
{
#ifdef HAVE_INTEL_RDSEED

    int ret;
    uint64_t rndTmp;

    for (; (sz / sizeof(uint64_t)) > 0; sz -= sizeof(uint64_t),
                                                    output += sizeof(uint64_t)) {
        ret = IntelRDseed64_r((uint64_t*)output);
        if (ret != 0)
            return ret;
    }
    if (sz == 0) return MR_E_SUCCESS;

    /* handle unaligned remainder */
    ret = IntelRDseed64_r(&rndTmp);
    if (ret != 0) return ret;

    memcpy(output, &rndTmp, sz);
    *(volatile uint64_t*)(&rndTmp) = 0;

    return MR_E_SUCCESS;


#else


	if ((sz % 4) == 0 && (((uint32_t)output) % 4) == 0)
	{
		uint32_t *uoutput = (uint32_t *)output;
		sz /= 4;
		for (int i = 0; i < sz; i++)
		{
			uoutput[i] = rand();
		}
	}
	else
	{
		for (int i = 0; i < sz; i++)
		{
			output[i] = (uint8_t)rand();
		}
	}

	return 0;
#endif
}


int CUSTOM_RAND_GENERATE_SEED_OS(void* os, uint8_t *output, uint32_t sz)
{
	return mr_rng_seed(output, sz);
}