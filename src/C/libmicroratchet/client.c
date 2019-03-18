#include "pch.h"
#include "microratchet.h"
#include "internal.h"

mr_ctx mrclient_create(mr_config* config)
{
	_mr_ctx* ctx;
	int r = mr_allocate(0, sizeof(_mr_ctx), &ctx);
	memset(ctx, 0, sizeof(_mr_ctx));
	ctx->sha_ctx = mr_sha_create(ctx);
	if (r != E_SUCCESS) return 0;
	return ctx;
}

int mrclient_process_initialization(mr_ctx ctx, const unsigned char* bytes, int numbytes)
{
	return E_INVALIDARGUMENT;
}

int mrclient_receive_data(mr_ctx ctx, const unsigned char* bytes, int numbytes, unsigned char** output, int spaceavail, int* outputspace)
{
	return E_INVALIDARGUMENT;
}

int mrclient_send_data(mr_ctx ctx, const unsigned char* data, int numbytes)
{
	return E_INVALIDARGUMENT;
}

void mrclient_destroy(mr_ctx _ctx)
{
	_mr_ctx* ctx = _ctx;
	if (ctx)
	{
		if (ctx->sha_ctx)
		{
			mr_sha_destroy(ctx->sha_ctx);
			ctx->sha_ctx = 0;
		}
		mr_free(ctx, ctx);
	}
}