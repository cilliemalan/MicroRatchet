#include "pch.h"
#include "microratchet.h"
#include "internal.h"



#define get_messageType(byte) (((byte) & 0xe0) >> 5)
#define set_messageType(byte, type) (((byte) & 0x1f) | (((type) & 0x07) << 5))
#define clear_messageType(byte) ((byte) & 0x1f)
#define is_initializationMessage(messageType) ((messageType == MSG_TYPE_INIT_REQ) || (messageType == MSG_TYPE_INIT_RES))
#define is_normalMessage(messageType) ((messageType == MSG_TYPE_NORMAL) || (messageType == MSG_TYPE_NORMAL_WITH_ECDH))
#define is_multipartMessage(messageType) (messageType == MSG_TYPE_MULTIPART)

static int get_isinitialized(_mr_ctx* ctx) { return 0; }
static int get_maximumMessageSize(_mr_ctx* ctx) { return ctx->config->mtu - MIN_OVERHEAD; }
static int get_maximumMessageSizeWithEcdh(_mr_ctx* ctx) { return ctx->config->mtu - OVERHEAD_WITH_ECDH; }

static int check_mtu(_mr_ctx* ctx)
{
	int minInitializedSize = INIT_RES_MSG_SIZE > INIT_REQ_MSG_SIZE ? INIT_RES_MSG_SIZE : INIT_REQ_MSG_SIZE;
	int minNormalSize = OVERHEAD_WITH_ECDH + MIN_MSG_SIZE;
	int minsize;

	if (get_isinitialized(ctx)) minsize = minInitializedSize > minNormalSize ? minInitializedSize : minNormalSize;
	else minsize = minNormalSize;

	if (ctx->config->mtu < minsize)
	{
		return E_INVALIDSIZE;
	}
	else
	{
		return E_SUCCESS;
	}
}

static int send_initializationRequest(_mr_ctx* ctx)
{

}

static int receive_initializationRequest(_mr_ctx* ctx, unsigned char* data, unsigned int datasize, unsigned char** initializationNonce, unsigned char** remoteEcdhForInit)
{

}

static int send_initializationResponse(_mr_ctx* ctx, unsigned char* initializationNonce, unsigned char* remoteEcdhForInit)
{

}

static int receive_initializationResponse(_mr_ctx* ctx, unsigned char* data, unsigned int datasize)
{

}

static int send_firstClientMessage(_mr_ctx* ctx)
{

}

static int receive_firstClientMessage(_mr_ctx* ctx, unsigned char* data, unsigned int datasize)
{

}

static int send_firstResponse(_mr_ctx* ctx)
{

}

static int receive_firstResponse(_mr_ctx* ctx, unsigned char* data, unsigned int datasize)
{

}

static int construct_and_send_message(_mr_ctx* ctx, int allowPad, int includeEcdh, _mr_ratchet_state* ratchet, int overrideMessageType)
{

}

static int deconstruct_message(_mr_ctx* ctx, unsigned char* data, unsigned int datasize, int expectMessageType, int overrideHasEcdh, unsigned char* output, unsigned int outputsize)
{

}

static int construct_and_send_multipart(_mr_ctx* ctx, unsigned char* data, unsigned int datasize)
{

}

static int deconstruct_multipart(_mr_ctx* ctx, unsigned char* data, unsigned int datasize, unsigned char* output, unsigned int outputsize)
{

}

static int process_initialization_internal(_mr_ctx* ctx, unsigned char* data, unsigned int datasize)
{

}

static int process_initialization(_mr_ctx* ctx, unsigned char* data, unsigned int datasize)
{

}

static int send_single(_mr_ctx* ctx, unsigned char* data, unsigned int datasize, int allowPad)
{

}

static int send_internal(_mr_ctx* ctx, unsigned char* data, unsigned int datasize, int allowPad)
{

}

static int receive_internal(_mr_ctx* ctx, unsigned char* data, unsigned int datasize, unsigned char* output, unsigned int outputsize)
{

}



mr_ctx mrclient_create(mr_config* config)
{
	_mr_ctx* ctx;
	int r = mr_allocate(0, sizeof(_mr_ctx), &ctx);
	memset(ctx, 0, sizeof(_mr_ctx));
	ctx->sha_ctx = mr_sha_create(ctx);
	if (r != E_SUCCESS) return 0;
	return ctx;
}

int mrclient_initiate_initialization(mr_ctx ctx, int force)
{
	return E_INVALIDARGUMENT;
}

int mrclient_receive_data(mr_ctx ctx, const unsigned char* data, unsigned int datasize, unsigned char** output, unsigned int* outputsize)
{
	return E_INVALIDARGUMENT;
}

int mrclient_send_data(mr_ctx ctx, const unsigned char* data, unsigned int datasize, int mustPad)
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