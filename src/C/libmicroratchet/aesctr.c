#include "pch.h"
#include "microratchet.h"
#include "internal.h"


int aesctr_init(_mr_aesctr_ctx *ctx, mr_aes_ctx aes, const unsigned char *iv, unsigned int ivsize)
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

int aesctr_process(_mr_aesctr_ctx *ctx, const unsigned char* data, unsigned int amount, unsigned char* output, unsigned int spaceavail)
{
	if (!data || !ctx || !output) return E_INVALIDARGUMENT;
	if (amount == 0) return E_SUCCESS;
	if (spaceavail < amount) return E_INVALIDARGUMENT;

	unsigned char *ctr = ctx->ctr;
	unsigned char ctrout[16];

	unsigned int i = 0;
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
