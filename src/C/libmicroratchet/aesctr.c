#include "pch.h"
#include "microratchet.h"
#include "internal.h"


mr_result_t aesctr_init(_mr_aesctr_ctx *ctx, mr_aes_ctx aes, const uint8_t *iv, uint32_t ivsize)
{
	if (!iv || !ctx || !aes) return E_INVALIDARGUMENT;

	ctx->aes_ctx = aes;
	memcpy(ctx->ctr, iv, ivsize > 16 ? 16 : ivsize);
	if (ivsize < 16)
	{
		memset(ctx->ctr + ivsize, 0, 16 - ivsize);
	}
	
	return E_SUCCESS;
}

mr_result_t aesctr_process(_mr_aesctr_ctx *ctx, const uint8_t* data, uint32_t amount, uint8_t* output, uint32_t spaceavail)
{
	if (!data || !ctx || !output) return E_INVALIDARGUMENT;
	if (amount == 0) return E_SUCCESS;
	if (spaceavail < amount) return E_INVALIDARGUMENT;

	uint8_t *ctr = ctx->ctr;
	uint8_t ctrout[16];

	uint32_t i = 0;
	while (i < amount)
	{
		_C(mr_aes_process(ctx->aes_ctx, ctr, 16, ctrout, 16));
		for (int j = 0; j < 16 && i < amount; j++, i++)
		{
			output[i] = ctrout[j] ^ data[i];
		}

		for (int z = 15; z >= 0 && ++ctr[z] == 0; z--);
	}

	return E_SUCCESS;
}
