#include "pch.h"
#include "microratchet.h"
#include "internal.h"


#define MINIMUMPAYLOAD_SIZE (INITIALIZATION_NONCE_SIZE)
#define MINIMUMOVERHEAD (NONCE_SIZE + MAC_SIZE) // 16
#define OVERHEADWITHECDH (MINIMUMOVERHEAD + ECNUM_SIZE) // 48
#define MINIMUMMESSAGE_SIZE (MINIMUMPAYLOAD_SIZE + MINIMUMOVERHEAD)
#define MINIMUMMAXIMUMMESSAGE_SIZE (OVERHEADWITHECDH + MINIMUMPAYLOAD_SIZE)
#define HEADERIV_SIZE 16

typedef struct aaa {
	int a;
	int b;
	int c;
} bbb;

mr_ctx mrclient_create(mr_config* config)
{
	// check config
	if (!config) return 0;
	if (config->maximum_message_size < MINIMUMMAXIMUMMESSAGE_SIZE) return 0;
	if (config->minimum_message_size < MINIMUMMESSAGE_SIZE) return 0;
	if (config->minimum_message_size > config->maximum_message_size) return 0;

	_mr_ctx* ctx;
	int r = mr_allocate(0, sizeof(_mr_ctx), &ctx);

	*ctx = (_mr_ctx){
		*config,
		mr_sha_create(ctx),
		mr_rng_create(ctx)
	};

	if (r != E_SUCCESS) return 0;
	return ctx;
}

static mr_result_t send_initialization_request(_mr_ctx* ctx, uint8_t* output, uint32_t spaceavail)
{
	if (!ctx->config.is_client) return E_INVALIDOP;
	if (!ctx->config.identity) return E_INVALIDOP;

	// message format:
	// nonce(16), pubkey(32), ecdh(32), padding(...), signature(64), mac(12)

	// 16 bytes nonce
	_C(mr_rng_generate(ctx->rng_ctx, ctx->init.client.initializationnonce, INITIALIZATION_NONCE_SIZE));

	// get the public key
	uint8_t pubkey[ECNUM_SIZE];
	_C(mr_ecdsa_getpublickey(ctx->config.identity, pubkey, sizeof(pubkey)));

	// generate new ECDH keypair for init message and root key
	uint8_t clientEcdhPub[ECNUM_SIZE];
	ctx->init.client.localecdhforinit = mr_ecdh_create(ctx);
	_C(mr_ecdh_generate(ctx->init.client.localecdhforinit, clientEcdhPub, sizeof(clientEcdhPub)));

	// nonce(16), <pubkey(32), ecdh(32), signature(64)>, mac(12)
	uint32_t initializationMessageSize = INITIALIZATION_NONCE_SIZE + ECNUM_SIZE * 4 + MAC_SIZE;
	uint32_t messageSize = max(ctx->config.minimum_message_size, initializationMessageSize);
	uint32_t initializationMessageSizeWithSignature = messageSize - MAC_SIZE;
	uint32_t initializationMessageSizeWithoutSignature = messageSize - MAC_SIZE - SIGNATURE_SIZE;
	uint32_t signatureOffset = messageSize - MAC_SIZE - SIGNATURE_SIZE;
	if (spaceavail < messageSize) return E_INVALIDSIZE;
	memcpy(output, ctx->init.client.initializationnonce, INITIALIZATION_NONCE_SIZE);
	memcpy(output + INITIALIZATION_NONCE_SIZE, pubkey, ECNUM_SIZE);
	memcpy(output + INITIALIZATION_NONCE_SIZE + ECNUM_SIZE, clientEcdhPub, ECNUM_SIZE);

	// sign the message
	uint8_t digest[DIGEST_SIZE];
	_C(mr_sha_init(ctx->sha_ctx));
	_C(mr_sha_process(ctx->sha_ctx, output, messageSize));
	_C(mr_sha_compute(ctx->sha_ctx, digest, sizeof(digest)));
	_C(mr_ecdsa_sign(ctx->config.identity, digest, DIGEST_SIZE, output + signatureOffset, spaceavail - signatureOffset));

	// encrypt the message with the application key
	mr_aes_ctx aes = mr_aes_create(ctx);
	_mr_aesctr_ctx cipher;
	if (!aes) return E_NOMEM;
	_C(mr_aes_init(aes, ctx->config.applicationKey, KEY_SIZE));
	_C(aesctr_init(&cipher, aes, ctx->init.client.initializationnonce, INITIALIZATION_NONCE_SIZE));
	_C(aesctr_process(&cipher,
		output + INITIALIZATION_NONCE_SIZE,
		initializationMessageSizeWithSignature - INITIALIZATION_NONCE_SIZE,
		output + INITIALIZATION_NONCE_SIZE,
		spaceavail - INITIALIZATION_NONCE_SIZE));
	mr_aes_destroy(aes);
	aes = 0;

	// calculate mac
	mr_poly_ctx mac = mr_poly_create(ctx);
	if (!mac) return E_NOMEM;
	_C(mr_poly_init(mac, ctx->config.applicationKey, KEY_SIZE, output, INITIALIZATION_NONCE_SIZE));
	_C(mr_poly_process(mac, output, messageSize - MAC_SIZE));
	_C(mr_poly_compute(mac, output + messageSize - MAC_SIZE, spaceavail - (messageSize - MAC_SIZE)));
	mr_poly_destroy(mac);
	return E_SUCCESS;
}

static mr_result_t receive_initialization_request(_mr_ctx* ctx, const uint8_t* data, uint32_t amount,
	uint8_t* initializationnonce, uint32_t initializationnoncespaceavail,
	uint8_t* remoteecdhforinit, uint32_t remoteecdhforinitspaceavail)
{
	return E_INVALIDOP;
}

static mr_result_t send_initialization_response(_mr_ctx* ctx,
	uint8_t* initializationnonce, uint32_t initializationnoncesize,
	uint8_t* remoteecdhforinit, uint32_t remoteecdhforinitsize,
	uint8_t* output, uint32_t spaceavail)
{
	return E_INVALIDOP;
}

static mr_result_t receive_initialization_response(_mr_ctx* ctx,
	const uint8_t* data, uint32_t amount)
{
	return E_INVALIDOP;
}

static mr_result_t send_first_client_message(_mr_ctx* ctx, uint8_t* output, uint32_t spaceavail)
{
	return E_INVALIDOP;
}

static mr_result_t receive_first_client_message(_mr_ctx* ctx,
	const uint8_t* data, uint32_t amount,
	const _mr_ratchet_state* step)
{
	return E_INVALIDOP;
}

static mr_result_t send_first_server_response(_mr_ctx* ctx, uint8_t* output, uint32_t spaceavail)
{
	return E_INVALIDOP;
}

static mr_result_t receive_first_server_response(_mr_ctx* ctx, uint8_t* data, uint32_t amount,
	const uint8_t* headerkey, uint32_t headerkeysize,
	const _mr_ratchet_state* step)
{
	return E_INVALIDOP;
}

static mr_result_t construct_message(_mr_ctx* ctx, const uint8_t* message, uint32_t amount,
	bool includeecdh,
	const _mr_ratchet_state* step)
{
	return E_INVALIDOP;
}

static mr_result_t interpret_mac(_mr_ctx* ctx, const uint8_t* payload, uint32_t amount,
	const uint8_t* overrideheaderkey, uint32_t overrideheaderkeysize,
	uint8_t** headerKeyUsed, _mr_ratchet_state** stepUsed, bool* usedNextHeaderKey, bool* usedApplicationKey)
{
	return E_INVALIDOP;
}

static mr_result_t deconstruct_message(_mr_ctx* ctx, const uint8_t* payload, uint32_t amount,
	const uint8_t* headerkey, uint32_t headerkeysize,
	const _mr_ratchet_state* step,
	bool usedNextKey)
{
	return E_INVALIDOP;
}

static mr_result_t process_initialization(_mr_ctx* ctx, const uint8_t* message, uint32_t amount,
	const uint8_t* headerkey, uint32_t headerkeysize,
	const _mr_ratchet_state* step,
	bool usedApplicationHeaderKey)
{
	return E_INVALIDOP;
}

mr_result_t mrclient_initiate_initialization(mr_ctx _ctx, bool force, uint8_t* message, uint32_t spaceavailable)
{
	_mr_ctx* ctx = _ctx;
	return E_INVALIDOP;
}

mr_result_t mrclient_receive(mr_ctx _ctx, const uint8_t* message, uint32_t messagesize, uint8_t* data, uint32_t spaceAvail)
{
	_mr_ctx* ctx = _ctx;
	return E_INVALIDOP;
}

mr_result_t mrclient_send_data(mr_ctx _ctx, const uint8_t* payload, uint32_t payloadsize, uint8_t* message, uint32_t spaceavailable)
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
		if (ctx->rng_ctx)
		{
			mr_rng_destroy(ctx->rng_ctx);
			ctx->rng_ctx = 0;
		}
		mr_free(ctx, ctx);
	}
}