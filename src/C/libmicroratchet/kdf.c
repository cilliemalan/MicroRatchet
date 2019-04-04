#include "pch.h"
#include "microratchet.h"
#include "internal.h"

int kdf_compute(mr_ctx mr_ctx, const unsigned char* key, unsigned int keylen, const unsigned char* info, unsigned int infolen, unsigned char* output, unsigned int outputlen)
{
	int r = E_SUCCESS;

	// initialize AES with key
	mr_aes_ctx aes = mr_aes_create(mr_ctx);
	r = mr_aes_init(aes, key, keylen);
	if (r != E_SUCCESS) goto exit;

	// initialization phase. Pass all the bytes of info into AES in kind-of CBC mode.
	unsigned char ctr[16];
	memset(ctr, 0, sizeof(ctr));
	int info_offset = 0;
	if (info)
	{
		while (infolen - info_offset > 0)
		{
			for (unsigned int i = 0; i < 16 && i + info_offset < infolen; i++)
			{
				ctr[i] ^= info[i + info_offset];
			}

			int r = mr_aes_process(aes, ctr, sizeof(ctr), ctr, sizeof(ctr));
			if (r != E_SUCCESS) goto exit;

			info_offset += 16;
		}
	}

	// processing phase - AES ctr mode using processed init as nonce, returning
	// the cipher stream as output.
	unsigned int output_offset = 0;
	while (output_offset < outputlen)
	{
		for (int z = sizeof(ctr) - 1; z >= 0 && ++ctr[z] == 0; z--);

		if (outputlen - output_offset >= 16)
		{
			int r = mr_aes_process(aes, ctr, sizeof(ctr), output + output_offset, sizeof(ctr));
			if (r != E_SUCCESS) goto exit;
		}
		else
		{
			int r = mr_aes_process(aes, ctr, sizeof(ctr), ctr, sizeof(ctr));
			if (r != E_SUCCESS) goto exit;
			memcpy(output + output_offset, ctr, outputlen - output_offset);
		}
		output_offset += 16;
	}

exit:
	if (aes) mr_aes_destroy(aes);

	return r;
}