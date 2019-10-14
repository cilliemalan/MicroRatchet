#include "pch.h"
#include "microratchet.h"
#include "internal.h"


mr_result_t aesctr_init(_mr_aesctr_ctx *ctx, mr_aes_ctx aes, const uint8_t *iv, uint32_t ivsize)
{
	FAILIF(!iv || !ctx || !aes, E_INVALIDARGUMENT, "!iv || !ctx || !aes")

	*ctx = (_mr_aesctr_ctx){ aes };
	memcpy(ctx->ctr, iv, ivsize > 16 ? 16 : ivsize);
	
	return E_SUCCESS;
}

mr_result_t aesctr_process(_mr_aesctr_ctx *ctx, const uint8_t* data, uint32_t amount, uint8_t* output, uint32_t spaceavail)
{
	FAILIF(!data || !ctx || !output, E_INVALIDARGUMENT, "!data || !ctx || !output")
	FAILIF(amount == 0, E_SUCCESS, "amount == 0")
	FAILIF(spaceavail < amount, E_INVALIDARGUMENT, "spaceavail < amount")

	uint8_t *ctr = ctx->ctr;
	uint8_t ctrout[16];

	uint32_t i = 0;
	while (i < amount)
	{
		_C(mr_aes_process(ctx->aes_ctx, ctr, 16, ctrout, 16));

		for (; ctx->ctrix < 16 && i < amount; ctx->ctrix++, i++)
		{
			output[i] = ctrout[ctx->ctrix] ^ data[i];
		}

		if (ctx->ctrix == 16)
		{
			for (int z = 15; z >= 0 && ++ctr[z] == 0; z--);
			ctx->ctrix = 0;
		}
	}

	return E_SUCCESS;
}
