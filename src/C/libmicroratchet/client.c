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

mr_result_t mrclient_initiate_initialization(mr_ctx _ctx, bool force, const uint8_t* message, uint32_t spaceavailable)
{
	_mr_ctx* ctx = _ctx;
	return E_INVALIDOP;
}

mr_result_t mrclient_receive(mr_ctx _ctx, const uint8_t* message, uint32_t messagesize, uint8_t* data, uint32_t spaceAvail)
{
	_mr_ctx* ctx = _ctx;
	return E_INVALIDOP;
}

mr_result_t mrclient_send_data(mr_ctx _ctx, const uint8_t* payload, uint32_t payloadsize, const uint8_t* message, uint32_t spaceavailable)
{
	_mr_ctx* ctx = _ctx;
	return E_INVALIDOP;
}

uint32_t mrclient_state_size_needed(mr_ctx _ctx)
{
	_mr_ctx* ctx = _ctx;
	return 0;
}

mr_result_t mrclient_state_store(mr_ctx _ctx, uint8_t* destination, uint32_t spaceavailable)
{
	_mr_ctx* ctx = _ctx;
	return E_INVALIDOP;
}

mr_result_t mrclient_state_load(mr_ctx _ctx, const uint8_t* data, uint32_t amount)
{
	_mr_ctx* ctx = _ctx;
	return E_INVALIDOP;
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