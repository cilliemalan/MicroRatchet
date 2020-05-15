#include "pch.h"
#include <microratchet.h>

mr_rng_ctx mr_rng_create(mr_ctx mr_ctx)
{
	return (mr_rng_ctx)(size_t)0xffffffff;
}

mr_result mr_rng_generate(mr_rng_ctx _ctx, uint8_t* output, uint32_t outputsize)
{
	// because random is used so infrequently, our implementation
	// just spits the seed material out directly
	mr_rng_seed(output, outputsize);

	return MR_E_SUCCESS;
}

void mr_rng_destroy(mr_rng_ctx _ctx)
{
}
