#include "pch.h"
#include "microratchet.h"
#include "internal.h"

// forward
static mr_result construct_message(_mr_ctx* ctx, uint8_t* message, uint32_t amount, uint32_t spaceavail, bool includeecdh, _mr_ratchet_state* step);
static mr_result deconstruct_message(_mr_ctx* ctx, uint8_t* message, uint32_t amount, uint8_t** payload, uint32_t* payloadsize, const uint8_t* headerkey, uint32_t headerkeysize, _mr_ratchet_state* step, bool usedNextKey);

static inline void be_packu32(uint32_t value, uint8_t* target)
{
	STATIC_ASSERT(sizeof(value) == 4, "int must be size 4");
	target[0] = (value >> 24) & 0xff;
	target[1] = (value >> 16) & 0xff;
	target[2] = (value >> 8) & 0xff;
	target[3] = value & 0xff;
}

static inline uint32_t be_unpacku32(uint8_t* target)
{
	return (target[0] << 24) | (target[1] << 16) | (target[2] << 8) | target[3];
}


static bool allzeroes(const uint8_t* d, uint32_t amt)
{
	for (uint32_t i = 0; i < amt; i++)
	{
		if (d[i] != 0) return false;
	}

	return true;
}

static mr_result computemac(_mr_ctx* ctx, uint8_t* data, uint32_t datasize, const uint8_t* key, uint32_t keysize, const uint8_t* iv, uint32_t ivsize)
{
	FAILIF(!ctx || !data || !key || !iv, MR_E_INVALIDARG, "Some of the required arguments were null");
	FAILIF(keysize != KEY_SIZE, MR_E_INVALIDSIZE, "The key size was invalid");
	FAILIF(ivsize < NONCE_SIZE, MR_E_INVALIDSIZE, "The nonce was too small");
	FAILIF(datasize < MAC_SIZE + 1, MR_E_INVALIDSIZE, "The data size was too small. Must be at least the size of a MAC plus one byte");

	mr_poly_ctx mac = mr_poly_create(ctx);
	FAILIF(!mac, MR_E_NOMEM, "Could not allocate a POLY1305 instance");
	mr_result result = MR_E_SUCCESS;
	_R(result, mr_poly_init(mac, key, keysize, iv, ivsize));
	_R(result, mr_poly_process(mac, data, datasize - MAC_SIZE));
	_R(result, mr_poly_compute(mac, data + datasize - MAC_SIZE, MAC_SIZE));
	mr_poly_destroy(mac);
	_C(result);

	LOGD("mac iv                ", iv, ivsize);
	LOGD("mac key               ", key, keysize);
	LOGD("mac computed          ", data + datasize - MAC_SIZE, MAC_SIZE);
	return MR_E_SUCCESS;
}

static mr_result verifymac(_mr_ctx* ctx, const uint8_t* data, uint32_t datasize, const uint8_t* key, uint32_t keysize, const uint8_t* iv, uint32_t ivsize, bool* result)
{
	FAILIF(!ctx || !data || !key || !iv || !result, MR_E_INVALIDARG, "Some of the required arguments were null");
	FAILIF(keysize != KEY_SIZE, MR_E_INVALIDSIZE, "The key size was invalid");
	FAILIF(ivsize < NONCE_SIZE, MR_E_INVALIDSIZE, "The nonce was too small");
	FAILIF(datasize < MAC_SIZE + 1, MR_E_INVALIDSIZE, "The data size was too small. Must be at least the size of a MAC plus one byte");

	*result = false;

	uint8_t computedmac[MAC_SIZE] = { 0 };
	mr_poly_ctx mac = mr_poly_create(ctx);
	FAILIF(!mac, MR_E_NOMEM, "Could not allocate a POLY1305 instance");
	mr_result rr = MR_E_SUCCESS;
	_R(rr, mr_poly_init(mac, key, keysize, iv, ivsize));
	_R(rr, mr_poly_process(mac, data, datasize - MAC_SIZE));
	_R(rr, mr_poly_compute(mac, computedmac, MAC_SIZE));
	LOGD("verify mac iv         ", iv, ivsize);
	LOGD("verify mac key        ", key, keysize);
	LOGD("verify mac computed   ", computedmac, MAC_SIZE);
	LOGD("verify mac compareto  ", data + datasize - MAC_SIZE, MAC_SIZE);
	*result = memcmp(computedmac, data + datasize - MAC_SIZE, MAC_SIZE) == 0;
	mr_poly_destroy(mac);
	_C(rr);
	return MR_E_SUCCESS;
}

static mr_result digest(_mr_ctx* ctx, const uint8_t* data, uint32_t datasize, uint8_t* digest, uint32_t digestsize)
{
	FAILIF(!ctx || !data || !digest, MR_E_INVALIDARG, "Some of the required arguments were null");
	FAILIF(digestsize < DIGEST_SIZE, MR_E_INVALIDSIZE, "The output space was smaller than the digest size");

	_C(mr_sha_init(ctx->sha_ctx));
	_C(mr_sha_process(ctx->sha_ctx, data, datasize));
	_C(mr_sha_compute(ctx->sha_ctx, digest, digestsize));
	return MR_E_SUCCESS;
}

static mr_result sign(_mr_ctx* ctx, uint8_t* data, uint32_t datasize, mr_ecdsa_ctx signer)
{
	FAILIF(!ctx || !data || !signer, MR_E_INVALIDARG, "Some of the required arguments were null");
	FAILIF(datasize < SIGNATURE_SIZE + 1, MR_E_INVALIDSIZE, "The data size was too small. Must be at least the size of a signature and one byte extra");

	uint8_t sha[DIGEST_SIZE];
	_C(digest(ctx, data, datasize - SIGNATURE_SIZE, sha, sizeof(sha)));
	_C(mr_ecdsa_sign(signer, sha, DIGEST_SIZE, data + datasize - SIGNATURE_SIZE, SIGNATURE_SIZE));
	LOGD("signature hash        ", sha, DIGEST_SIZE);
	LOGD("signature             ", data + datasize - SIGNATURE_SIZE, SIGNATURE_SIZE);
	return MR_E_SUCCESS;
}

static mr_result verifysig(_mr_ctx* ctx, const uint8_t* data, uint32_t datasize, const uint8_t* pubkey, uint32_t pubkeysize, bool* result)
{
	FAILIF(!ctx || !data || !pubkey || !result, MR_E_INVALIDARG, "Some of the required arguments were null");
	FAILIF(datasize < SIGNATURE_SIZE + 1, MR_E_INVALIDSIZE, "The data size was too small. Must be at least the size of a signature and one byte extra");

	*result = false;
	uint8_t sha[DIGEST_SIZE];
	uint32_t sigresult = 0;
	_C(digest(ctx, data, datasize - SIGNATURE_SIZE, sha, sizeof(sha)));
	_C(mr_ecdsa_verify_other(data + datasize - SIGNATURE_SIZE, SIGNATURE_SIZE,
		sha, DIGEST_SIZE,
		pubkey, pubkeysize,
		&sigresult));
	LOGD("verify signature hash ", sha, DIGEST_SIZE);
	LOGD(sigresult ? "verify signature GOOD " : "verify signature BAD  ", data + datasize - SIGNATURE_SIZE, SIGNATURE_SIZE);
	*result = !!sigresult;
	return MR_E_SUCCESS;
}

static mr_result crypt(_mr_ctx* ctx, uint8_t* data, uint32_t datasize, const uint8_t* key, uint32_t keysize, const uint8_t* iv, uint32_t ivsize)
{
	FAILIF(!ctx || !data || !key || !iv, MR_E_INVALIDARG, "Some of the required arguments were null");
	FAILIF(datasize < 1, MR_E_INVALIDSIZE, "At least one byte of data must be specified");
	FAILIF(keysize != KEY_SIZE && keysize != MSG_KEY_SIZE, MR_E_INVALIDSIZE, "The key size was invalid");
	FAILIF(ivsize < NONCE_SIZE, MR_E_INVALIDSIZE, "The IV size was to small");

	LOGD("crypt with iv         ", iv, ivsize);
	LOGD("crypt with key        ", key, keysize);

	mr_aes_ctx aes = mr_aes_create(ctx);
	_mr_aesctr_ctx cipher;
	FAILIF(!aes, MR_E_NOMEM, "Could not allocate AES");
	mr_result result = MR_E_SUCCESS;
	_R(result, mr_aes_init(aes, key, keysize));
	_R(result, aesctr_init(&cipher, aes, iv, ivsize));
	_R(result, aesctr_process(&cipher, data, datasize, data, datasize));
	mr_aes_destroy(aes);
	_C(result);
	return MR_E_SUCCESS;
}

mr_ctx mr_ctx_create(const mr_config* config)
{
	if (!config) return 0;

	// allocate memory
	_mr_ctx* ctx;
	int r = mr_allocate(0, sizeof(_mr_ctx), (void**)&ctx);
	if (r != MR_E_SUCCESS || !ctx) return 0;

	// clear
	memset(ctx, 0, sizeof(_mr_ctx));

	// asign some stuff
	memcpy(&ctx->config, config, sizeof(mr_config));
	ctx->sha_ctx = mr_sha_create(ctx);
	ctx->rng_ctx = mr_rng_create(ctx);

	return ctx;
}

mr_result mr_ctx_set_identity(mr_ctx _ctx, mr_ecdsa_ctx identity, bool destroy_with_context)
{
	_mr_ctx* ctx = (_mr_ctx*)_ctx;
	FAILIF(!ctx, MR_E_INVALIDARG, "The context given was null");
	FAILIF(!identity, MR_E_INVALIDARG, "The identity given was null");

	ctx->identity = identity;
	ctx->owns_identity = destroy_with_context;
	return MR_E_SUCCESS;
}

static mr_result send_initialization_request(_mr_ctx* ctx, uint8_t* output, uint32_t spaceavail)
{
	FAILIF(!ctx || !output, MR_E_INVALIDARG, "Some of the required parameters were null");
	FAILIF(!ctx->config.is_client, MR_E_INVALIDOP, "Only the client can send an initialization request");
	FAILIF(spaceavail < INIT_REQ_MSG_SIZE, MR_E_INVALIDSIZE, "The space avaialble was less than the minimum init request message size");
	FAILIF(!ctx->identity, MR_E_INVALIDOP, "The session does not have an identity");
	FAILIF(!ctx->init.client, MR_E_INVALIDOP, "Client initialization state is null");

	LOG("--send_initialization_request");

	// message format:
	// nonce(16), pubkey(32), ecdh(32), padding(...), signature(64), mac(12)

	// 16 bytes nonce
	_C(mr_rng_generate(ctx->rng_ctx, ctx->init.client->initializationnonce, INITIALIZATION_NONCE_SIZE));
	LOGD("Initialization Nonce  ", ctx->init.client->initializationnonce, INITIALIZATION_NONCE_SIZE);

	// get the public key
	uint8_t pubkey[ECNUM_SIZE];
	_C(mr_ecdsa_getpublickey(ctx->identity, pubkey, sizeof(pubkey)));
	LOGD("client public key     ", pubkey, sizeof(pubkey));

	// generate new ECDH keypair for init message and root key
	uint8_t clientEcdhPub[ECNUM_SIZE];
	if (ctx->init.client->localecdhforinit) mr_ecdh_destroy(ctx->init.client->localecdhforinit);
	ctx->init.client->localecdhforinit = mr_ecdh_create(ctx);
	_C(mr_ecdh_generate(ctx->init.client->localecdhforinit, clientEcdhPub, sizeof(clientEcdhPub)));
	LOGD("client ecdh           ", clientEcdhPub, sizeof(clientEcdhPub));

	// nonce(16), <pubkey(32), ecdh(32), signature(64)>, mac(12)
	uint32_t macOffset = spaceavail - MAC_SIZE;
	memcpy(output, ctx->init.client->initializationnonce, INITIALIZATION_NONCE_SIZE);
	memcpy(output + INITIALIZATION_NONCE_SIZE, pubkey, ECNUM_SIZE);
	memcpy(output + INITIALIZATION_NONCE_SIZE + ECNUM_SIZE, clientEcdhPub, ECNUM_SIZE);

	// sign the message
	_C(sign(ctx, output, macOffset, ctx->identity));

	// encrypt the message with the application key
	_C(crypt(ctx,
		output + INITIALIZATION_NONCE_SIZE, spaceavail - INITIALIZATION_NONCE_SIZE - MAC_SIZE,
		ctx->config.applicationKey, KEY_SIZE,
		output, INITIALIZATION_NONCE_SIZE));

	// calculate mac
	_C(computemac(ctx,
		output, spaceavail,
		ctx->config.applicationKey, KEY_SIZE,
		output, INITIALIZATION_NONCE_SIZE));

	return MR_E_SUCCESS;
}

static mr_result receive_initialization_request(_mr_ctx* ctx, uint8_t* data, uint32_t amount,
	uint8_t** initializationnonce, uint32_t* initializationnoncesize,
	uint8_t** remoteecdhforinit, uint32_t* remoteecdhforinitsize)
{
	FAILIF(!ctx || !data || !initializationnonce ||
		!initializationnoncesize || !remoteecdhforinit ||
		!remoteecdhforinitsize, MR_E_INVALIDARG, "Some of the required arguments were null");
	FAILIF(amount < INIT_REQ_MSG_SIZE, MR_E_INVALIDSIZE, "The space amount of data was less than the minimum init request message size");
	FAILIF(ctx->config.is_client, MR_E_INVALIDOP, "Only the server can receive an init request");
	FAILIF(!ctx->identity, MR_E_INVALIDOP, "The session does not have an identity");
	FAILIF(!ctx->init.server, MR_E_INVALIDOP, "Server initialization state is null");

	LOG("--receive_initialization_request");

	*initializationnonce = 0;
	*initializationnoncesize = 0;
	*remoteecdhforinit = 0;
	*remoteecdhforinitsize = 0;

	// nonce(16), pubkey(32), ecdh(32), pading(...), signature(64), mac(12)

	// decrypt the message
	_C(crypt(ctx,
		data + INITIALIZATION_NONCE_SIZE, amount - INITIALIZATION_NONCE_SIZE - MAC_SIZE,
		ctx->config.applicationKey, KEY_SIZE,
		data, INITIALIZATION_NONCE_SIZE));

	uint32_t macOffset = amount - MAC_SIZE;
	uint32_t clientPublicKeyOffset = INITIALIZATION_NONCE_SIZE;

	if (!allzeroes(ctx->init.server->clientpublickey, ECNUM_SIZE))
	{
		if (memcmp(ctx->init.server->clientpublickey, data + clientPublicKeyOffset, ECNUM_SIZE) != 0)
		{
			FAILMSG(MR_E_INVALIDOP, "The server was initialized before with a different public key");
		}
		else
		{
			if (ctx->init.server->localratchetstep0)
			{
				mr_ecdh_destroy(ctx->init.server->localratchetstep0);
			}
			if (ctx->init.server->localratchetstep1)
			{
				mr_ecdh_destroy(ctx->init.server->localratchetstep1);
			}

			// the client wants to reinitialize. Reset state.
			memset(ctx->init.server, 0, sizeof(_mr_initialization_state_server));
		}
	}

	// verify the signature
	bool sigvalid = false;
	_C(verifysig(ctx,
		data, macOffset,
		data + clientPublicKeyOffset, ECNUM_SIZE,
		&sigvalid));

	// store the client public key
	memcpy(ctx->init.server->clientpublickey, data + clientPublicKeyOffset, ECNUM_SIZE);

	// set all the pointers
	*initializationnonce = data;
	*initializationnoncesize = INITIALIZATION_NONCE_SIZE;
	*remoteecdhforinit = data + INITIALIZATION_NONCE_SIZE + ECNUM_SIZE;
	*remoteecdhforinitsize = ECNUM_SIZE;

	return MR_E_SUCCESS;
}

static mr_result send_initialization_response(_mr_ctx* ctx,
	uint8_t* initializationnonce, uint32_t initializationnoncesize,
	uint8_t* remoteecdhforinit, uint32_t remoteecdhforinitsize,
	uint8_t* output, uint32_t spaceavail)
{
	FAILIF(!ctx || !initializationnonce || !remoteecdhforinit || !output, MR_E_INVALIDARG, "Some of the required parameters were null");
	FAILIF(ctx->config.is_client, MR_E_INVALIDOP, "Only the server can send an initialization response");
	FAILIF(initializationnoncesize != INITIALIZATION_NONCE_SIZE, MR_E_INVALIDSIZE, "The initialization nonce size was invalid");
	FAILIF(remoteecdhforinitsize != ECNUM_SIZE, MR_E_INVALIDSIZE, "The ECDH public key was of an incorrect size");
	FAILIF(spaceavail < INIT_RES_MSG_SIZE, MR_E_INVALIDSIZE, "The amount of space available is less than the minimum space required for an initialization response");
	FAILIF(!ctx->init.server, MR_E_INVALIDOP, "Server initialization state is null");

	LOG("--send_initialization_response");

	// store the passed in parms because we're going to overwrite the buffer
	// this is because initializationnonce is inside output
	uint8_t tmp1[INITIALIZATION_NONCE_SIZE];
	memcpy(tmp1, initializationnonce, INITIALIZATION_NONCE_SIZE);
	initializationnonce = tmp1;

	// message format:
	// new nonce(16), ecdh pubkey(32),
	// <nonce from init request(16), server pubkey(32), 
	// new ecdh pubkey(32) x2, Padding(...), signature(64)>, mac(12) = 236 bytes

	// generate a nonce and new ecdh parms
	uint8_t* serverNonce = ctx->init.server->nextinitializationnonce;
	uint8_t* rootKey = ctx->init.server->rootkey;
	_C(mr_rng_generate(ctx->rng_ctx, serverNonce, INITIALIZATION_NONCE_SIZE));
	LOGD("server nonce          ", serverNonce, INITIALIZATION_NONCE_SIZE);
	uint8_t rootPreEcdhPubkey[ECNUM_SIZE];
	mr_ecdh_ctx rootPreEcdh = mr_ecdh_create(ctx);
	FAILIF(!rootPreEcdh, MR_E_NOMEM, "Could not allocate ECDH parameters");
	mr_result result = MR_E_SUCCESS;
	_R(result, mr_ecdh_generate(rootPreEcdh, rootPreEcdhPubkey, sizeof(rootPreEcdhPubkey)));
	LOGD("root pre ecdh pub     ", rootPreEcdhPubkey, ECNUM_SIZE);

	// generate server ECDH for root key and root key
	uint8_t rootPreKey[KEY_SIZE];
	_R(result, mr_ecdh_derivekey(rootPreEcdh, remoteecdhforinit, remoteecdhforinitsize, rootPreKey, sizeof(rootPreKey)));
	_R(result, digest(ctx, rootPreKey, sizeof(rootPreKey), rootPreKey, sizeof(rootPreKey)));
	_R(result, kdf_compute(ctx,
		rootPreKey, KEY_SIZE,
		serverNonce, INITIALIZATION_NONCE_SIZE,
		rootKey, KEY_SIZE * 3)); //rootkey, firstsendheaderkey, firstreceiveheaderkey
	LOGD("root pre key          ", rootPreKey, KEY_SIZE);
	LOGD("root key              ", ctx->init.server->rootkey, KEY_SIZE);
	LOGD("first send header k   ", ctx->init.server->firstsendheaderkey, KEY_SIZE);
	LOGD("first recv header k   ", ctx->init.server->firstreceiveheaderkey, KEY_SIZE);

	mr_ecdh_destroy(rootPreEcdh);
	_C(result);

	// generate two server ECDH. One for ratchet 0 sending key and one for the next
	// this is enough for the server to generate a receiving chain key and sending
	// chain key as soon as the client sends a sending chain key
	uint8_t rre0[ECNUM_SIZE];
	if (ctx->init.server->localratchetstep0) mr_ecdh_destroy(ctx->init.server->localratchetstep0);
	ctx->init.server->localratchetstep0 = mr_ecdh_create(ctx);
	FAILIF(!ctx->init.server->localratchetstep0, MR_E_NOMEM, "Could not allocate ECDH parameters");
	_C(mr_ecdh_generate(ctx->init.server->localratchetstep0, rre0, sizeof(rre0)));
	LOGD("rre0                  ", rre0, ECNUM_SIZE);
	uint8_t rre1[ECNUM_SIZE];
	if (ctx->init.server->localratchetstep1) mr_ecdh_destroy(ctx->init.server->localratchetstep1);
	ctx->init.server->localratchetstep1 = mr_ecdh_create(ctx);
	FAILIF(!ctx->init.server->localratchetstep1, MR_E_NOMEM, "Could not allocate ECDH parameters");
	_C(mr_ecdh_generate(ctx->init.server->localratchetstep1, rre1, sizeof(rre1)));
	LOGD("rre1                  ", rre1, ECNUM_SIZE);

	uint32_t macOffset = spaceavail - MAC_SIZE;
	uint32_t encryptedPayloadOffset = INITIALIZATION_NONCE_SIZE + ECNUM_SIZE;
	uint32_t encryptedPayloadSize = macOffset - encryptedPayloadOffset;

	// construct the message
	memcpy(output, serverNonce, INITIALIZATION_NONCE_SIZE);
	memcpy(output + INITIALIZATION_NONCE_SIZE, rootPreEcdhPubkey, ECNUM_SIZE);

	// construct the to-be-encrypted part
	uint8_t* encryptedPayload = output + encryptedPayloadOffset;
	// server nonce
	memcpy(encryptedPayload,
		initializationnonce, INITIALIZATION_NONCE_SIZE);
	// server public key
	_C(mr_ecdsa_getpublickey(ctx->identity, encryptedPayload + INITIALIZATION_NONCE_SIZE, ECNUM_SIZE));
	// server ratchet 0
	memcpy(encryptedPayload + INITIALIZATION_NONCE_SIZE + ECNUM_SIZE,
		rre0, ECNUM_SIZE);
	// server ratchet 1
	memcpy(encryptedPayload + INITIALIZATION_NONCE_SIZE + ECNUM_SIZE * 2,
		rre1, ECNUM_SIZE);

	// sign the message
	_C(sign(ctx, output, macOffset, ctx->identity));

	// encrypt the encrypted part
	_C(crypt(ctx,
		encryptedPayload, encryptedPayloadSize,
		rootPreKey, KEY_SIZE,
		serverNonce, INITIALIZATION_NONCE_SIZE));

	// encrypt the header
	_C(crypt(ctx,
		output, encryptedPayloadOffset,
		ctx->config.applicationKey, KEY_SIZE,
		encryptedPayload + encryptedPayloadSize - HEADERIV_SIZE, HEADERIV_SIZE));

	// calculate mac
	_C(computemac(ctx,
		output, spaceavail,
		ctx->config.applicationKey, KEY_SIZE,
		output, INITIALIZATION_NONCE_SIZE));

	return MR_E_SUCCESS;
}

static mr_result receive_initialization_response(_mr_ctx* ctx,
	uint8_t* data, uint32_t amount)
{
	FAILIF(!ctx || !data, MR_E_INVALIDARG, "Some of the required arguments were null");
	FAILIF(!ctx->config.is_client, MR_E_INVALIDOP, "Only the client can receive an initialization response");
	FAILIF(amount < INIT_RES_MSG_SIZE, MR_E_INVALIDARG, "The message was smaller than the minimum init response message size");
	FAILIF(!ctx->init.client, MR_E_INVALIDOP, "Client initialization state is null");

	uint32_t macOffset = amount - MAC_SIZE;
	uint32_t ecdhOffset = INITIALIZATION_NONCE_SIZE;
	uint32_t headerIvOffset = macOffset - HEADERIV_SIZE;
	uint32_t headerSize = INITIALIZATION_NONCE_SIZE + ECNUM_SIZE;
	uint32_t payloadSize = amount - headerSize - MAC_SIZE;
	uint8_t* payload = data + headerSize;

	LOG("--receive_initialization_response");

	// new nonce(16), ecdh pubkey(32), <nonce(16), server pubkey(32), 
	// new ecdh pubkey(32) x2, signature(64)>, mac(12)

	// decrypt header
	_C(crypt(ctx,
		data, headerSize,
		ctx->config.applicationKey, KEY_SIZE,
		data + headerIvOffset, HEADERIV_SIZE));

	// decrypt payload
	uint8_t rootPreKey[KEY_SIZE];
	_C(mr_ecdh_derivekey(ctx->init.client->localecdhforinit,
		data + ecdhOffset, ECNUM_SIZE,
		rootPreKey, sizeof(rootPreKey)));
	_C(digest(ctx, rootPreKey, sizeof(rootPreKey), rootPreKey, sizeof(rootPreKey)));
	LOGD("remote ecdh pub       ", data + ecdhOffset, ECNUM_SIZE);
	LOGD("root pre key          ", rootPreKey, KEY_SIZE);
	_C(crypt(ctx,
		payload, payloadSize,
		rootPreKey, KEY_SIZE,
		data, INITIALIZATION_NONCE_SIZE));

	LOGD("sent init nonce       ", payload, INITIALIZATION_NONCE_SIZE);
	LOGD("client init nonce     ", ctx->init.client->initializationnonce, INITIALIZATION_NONCE_SIZE);

	// ensure the nonce matches
	if (memcmp(payload, ctx->init.client->initializationnonce, INITIALIZATION_NONCE_SIZE) != 0)
	{
		FAILMSG(MR_E_INVALIDOP, "The received initialization nonce did not match the one sent earlier");
	}

	// verify the signature
	bool sigvalid = false;
	_C(verifysig(ctx,
		data, headerSize + payloadSize,
		payload + INITIALIZATION_NONCE_SIZE, ECNUM_SIZE,
		&sigvalid));
	if (!sigvalid)
	{
		FAILMSG(MR_E_INVALIDOP, "The signature sent by the server was invalid.");
	}

	// store the nonce we got from the server
	memcpy(ctx->init.client->initializationnonce, data, INITIALIZATION_NONCE_SIZE);
	LOGD("server init nonce     ", data, INITIALIZATION_NONCE_SIZE);

	// we now have enough information to construct our double ratchet
	mr_result result = MR_E_SUCCESS;
	uint8_t localStep0Pub[ECNUM_SIZE];
	mr_ecdh_ctx localStep0 = mr_ecdh_create(ctx);
	FAILIF(!localStep0, MR_E_NOMEM, "Could not allocate ECDH parameters");
	_R(result, mr_ecdh_generate(localStep0, localStep0Pub, sizeof(localStep0Pub)));
	LOGD("local step0 pub       ", localStep0Pub, ECNUM_SIZE);
	uint8_t localStep1Pub[ECNUM_SIZE];
	mr_ecdh_ctx localStep1 = mr_ecdh_create(ctx);
	FAILIF(!localStep1, MR_E_NOMEM, "Could not allocate ECDH parameters");
	_R(result, mr_ecdh_generate(localStep1, localStep1Pub, sizeof(localStep1Pub)));
	LOGD("local step1 pub       ", localStep1Pub, ECNUM_SIZE);

	// initialize client root key and ecdh ratchet
	uint8_t genKeys[KEY_SIZE * 3];
	_R(result, kdf_compute(ctx,
		rootPreKey, KEY_SIZE,
		data, INITIALIZATION_NONCE_SIZE,
		genKeys, sizeof(genKeys)));
	uint8_t* rootKey = genKeys;
	uint8_t* receiveHeaderKey = genKeys + KEY_SIZE;
	uint8_t* sendHeaderKey = genKeys + KEY_SIZE * 2;
	LOGD("root key              ", rootKey, KEY_SIZE);
	LOGD("first recv header k   ", receiveHeaderKey, KEY_SIZE);
	LOGD("first send header k   ", sendHeaderKey, KEY_SIZE);

	uint8_t* remoteRatchetEcdh0 = payload + INITIALIZATION_NONCE_SIZE + ECNUM_SIZE;
	uint8_t* remoteRatchetEcdh1 = payload + INITIALIZATION_NONCE_SIZE + ECNUM_SIZE * 2;

	_mr_ratchet_state* ratchets = 0;
	_R(result, mr_allocate(ctx, sizeof(_mr_ratchet_state) * 2, (void**)&ratchets));

	_R(result, ratchet_initialize_client(ctx, &ratchets[0], &ratchets[1],
		rootKey, KEY_SIZE,
		remoteRatchetEcdh0, ECNUM_SIZE,
		remoteRatchetEcdh1, ECNUM_SIZE,
		localStep0,
		receiveHeaderKey, KEY_SIZE,
		sendHeaderKey, KEY_SIZE,
		localStep1));
	_R(result, ratchet_add(ctx, &ratchets[0]));
	_R(result, ratchet_add(ctx, &ratchets[1]));

	if (result != MR_E_SUCCESS)
	{
		if (localStep0) mr_ecdh_destroy(localStep0);
		if (localStep1) mr_ecdh_destroy(localStep1);
		if (ratchets)
		{
			if (ratchets[0].num) ratchet_destroy(ctx, ratchets[0].num);
			if (ratchets[1].num) ratchet_destroy(ctx, ratchets[1].num);
		}
	}

	if (ratchets)
	{
		mr_free(ctx, ratchets);
	}

	_C(result);

	return MR_E_SUCCESS;
}

static mr_result send_first_client_message(_mr_ctx* ctx, uint8_t* output, uint32_t spaceavail)
{
	FAILIF(!ctx->config.is_client, MR_E_INVALIDOP, "Only the client can send the first message");
	FAILIF(!ctx->init.client, MR_E_INVALIDOP, "Client initialization state is null");

	_mr_ratchet_state* secondToLast;
	_C(ratchet_getsecondtolast(ctx, &secondToLast));

	memcpy(output, ctx->init.client->initializationnonce, INITIALIZATION_NONCE_SIZE);

	return construct_message(ctx, output, INITIALIZATION_NONCE_SIZE, spaceavail, true, secondToLast);
}

static mr_result receive_first_client_message(_mr_ctx* ctx, uint8_t* data, uint32_t amount)
{
	FAILIF(ctx->config.is_client, MR_E_INVALIDOP, "Only the server can receive the first client message");
	FAILIF(!ctx->init.server, MR_E_INVALIDOP, "Server initialization state is null");

	uint8_t* payload = 0;
	uint32_t payloadSize = 0;
	_C(deconstruct_message(ctx,
		data, amount,
		&payload, &payloadSize,
		ctx->init.server->firstreceiveheaderkey, KEY_SIZE,
		0, false));

	if (payloadSize < INITIALIZATION_NONCE_SIZE || memcmp(payload, ctx->init.server->nextinitializationnonce, INITIALIZATION_NONCE_SIZE) != 0)
	{
		FAILMSG(MR_E_INVALIDOP, "The nonce received did not match the one sent earlier");
	}

	return MR_E_SUCCESS;
}

static mr_result send_first_server_response(_mr_ctx* ctx, uint8_t* output, uint32_t spaceavail)
{
	FAILIF(ctx->config.is_client, MR_E_INVALIDOP, "Only the server can send the first server response");
	FAILIF(!ctx->init.server, MR_E_INVALIDOP, "Server initialization state is null");

	memcpy(output, ctx->init.server->nextinitializationnonce, INITIALIZATION_NONCE_SIZE);
	_mr_ratchet_state* laststep;
	_C(ratchet_getlast(ctx, &laststep));
	_C(construct_message(ctx, output, INITIALIZATION_NONCE_SIZE, spaceavail, false, laststep));

	return MR_E_SUCCESS;
}

static mr_result receive_first_server_response(_mr_ctx* ctx, uint8_t* data, uint32_t amount,
	const uint8_t* headerkey, uint32_t headerkeysize,
	_mr_ratchet_state* step)
{
	FAILIF(!ctx->config.is_client, MR_E_INVALIDOP, "Only the client can receive the first server response");
	FAILIF(!ctx->init.client, MR_E_INVALIDOP, "Client initialization state is null");


	uint8_t* payload = 0;
	uint32_t payloadsize = 0;
	_C(deconstruct_message(ctx,
		data, amount,
		&payload, &payloadsize,
		headerkey, headerkeysize,
		step, false));
	if (!payload || payloadsize < INITIALIZATION_NONCE_SIZE ||
		memcmp(payload, ctx->init.client->initializationnonce, INITIALIZATION_NONCE_SIZE) != 0)
	{
		FAILMSG(MR_E_INVALIDOP, "The nonce received did not match the one sent earlier");
	}

	return MR_E_SUCCESS;
}

static mr_result construct_message(_mr_ctx* ctx, uint8_t* message, uint32_t amount, uint32_t spaceavail,
	bool includeecdh,
	_mr_ratchet_state* step)
{
	FAILIF(!ctx || !message, MR_E_INVALIDARG, "Some of the required arguments were null");
	FAILIF(includeecdh && spaceavail < MIN_MESSAGE_SIZE_WITH_ECDH, MR_E_INVALIDSIZE, "When ECDH is included in the total message will be at least 64 bytes");
	FAILIF(!includeecdh && spaceavail < MIN_MESSAGE_SIZE, MR_E_INVALIDSIZE, "When ECDH is not included the total message will be at least 32 bytes");
	FAILIF(includeecdh && spaceavail < amount + OVERHEAD_WITH_ECDH, MR_E_INVALIDSIZE, "When ECDH is included in the message there must be at least 48 bytes of extra space");
	FAILIF(!includeecdh && spaceavail < amount + OVERHEAD_WITHOUT_ECDH, MR_E_INVALIDSIZE, "When ECDH is not included there must be at least 16 bytes of extra space");

	LOG("--construct_message");

	// message format:
	// <nonce (4)>, <payload, padding>, mac(12)
	// -OR-
	// <nonce (4), ecdh (32)>, <payload, padding>, mac(12)

	// get the payload key and nonce
	uint8_t payloadKey[MSG_KEY_SIZE];
	uint32_t generation;
	_C(chain_ratchetforsending(ctx, &step->sendingchain, payloadKey, sizeof(payloadKey), &generation));

	// make sure the first bit is not set as we use that bit to indicate
	// the presence of new ECDH parameters
	if (generation > 0x7fffffff)
	{
		FAILMSG(MR_E_INVALIDOP, "The generation exceeded 2^31. ECDH key exchange needs to happen before another message can be sent.");
	}

	// calculate some sizes
	uint32_t headersize = NONCE_SIZE + (includeecdh ? ECNUM_SIZE : 0);
	uint32_t payloadSize = spaceavail - headersize - MAC_SIZE;
	uint32_t amountAfterPayload = spaceavail - amount - headersize - MAC_SIZE;
	uint32_t headerIvOffset = spaceavail - MAC_SIZE - HEADERIV_SIZE;

	// build the payload <payload, padding>
	memmove(message + headersize, message, amount);
	memset(message + headersize + amount, 0, amountAfterPayload);
	LOGD("[payload]             ", message + headersize, amount);

	// copy in the nonce
	be_packu32(generation, message);
	LOGD("[nonce]               ", message, NONCE_SIZE);

	// encrypt the payload
	_C(crypt(ctx, message + headersize, payloadSize, payloadKey, MSG_KEY_SIZE, message, NONCE_SIZE));

	// copy in ecdh parms if needed
	if (includeecdh)
	{
		_C(mr_ecdh_getpublickey(step->ecdhkey, message + NONCE_SIZE, ECNUM_SIZE));
		LOGD("[ecdh]                ", message + NONCE_SIZE, ECNUM_SIZE);
		message[0] |= 0b10000000;
	}
	else
	{
		message[0] &= 0b01111111;
	}

	// encrypt the header using the header key and using the
	// last 16 bytes of the message as the nonce.
	_C(crypt(ctx, message, headersize, step->sendheaderkey, KEY_SIZE, message + headerIvOffset, HEADERIV_SIZE));
	LOGD("[ecdh]                ", message + NONCE_SIZE, ECNUM_SIZE);

	// mac the message
	_C(computemac(ctx, message, spaceavail, step->sendheaderkey, KEY_SIZE, message, MACIV_SIZE));
	LOGD("[mac]                 ", message + spaceavail - MAC_SIZE, MAC_SIZE);

	return MR_E_SUCCESS;
}

static mr_result interpret_mac(_mr_ctx* ctx, const uint8_t* message, uint32_t amount,
	uint8_t** headerKeyUsed, _mr_ratchet_state** stepUsed, bool* usedNextHeaderKey)
{
	*headerKeyUsed = 0;
	*stepUsed = 0;
	*usedNextHeaderKey = false;

	bool macmatches = false;

	// check ratchet header keys
	if (ctx->ratchets[0].num)
	{
		for (int i = NUM_RATCHETS - 1; i >= 0; i--)
		{
			if (ctx->ratchets[i].num && !allzeroes(ctx->ratchets[i].receiveheaderkey, KEY_SIZE))
			{
				_C(verifymac(ctx, message, amount, ctx->ratchets[i].receiveheaderkey, KEY_SIZE, message, MACIV_SIZE, &macmatches));
				if (macmatches)
				{
					*headerKeyUsed = ctx->ratchets[i].receiveheaderkey;
					*stepUsed = &ctx->ratchets[i];
					return MR_E_SUCCESS;
				}
				else if (!allzeroes(ctx->ratchets[i].nextreceiveheaderkey, KEY_SIZE))
				{
					_C(verifymac(ctx, message, amount, ctx->ratchets[i].nextreceiveheaderkey, KEY_SIZE, message, MACIV_SIZE, &macmatches));
					if (macmatches)
					{
						*headerKeyUsed = ctx->ratchets[i].nextreceiveheaderkey;
						*stepUsed = &ctx->ratchets[i];
						*usedNextHeaderKey = true;
						return MR_E_SUCCESS;
					}
				}
			}
		}
	}

	// check application header key
	_C(verifymac(ctx, message, amount, ctx->config.applicationKey, KEY_SIZE, message, MACIV_SIZE, &macmatches));
	if (macmatches)
	{
		*headerKeyUsed = ctx->config.applicationKey;
		return MR_E_SUCCESS;
	}
	else if (!ctx->config.is_client)
	{
		if (!ctx->init.initialized && ctx->ratchets[0].num == 0 && ctx->init.server && !allzeroes(ctx->init.server->firstreceiveheaderkey, KEY_SIZE))
		{
			_C(verifymac(ctx, message, amount, ctx->init.server->firstreceiveheaderkey, KEY_SIZE, message, MACIV_SIZE, &macmatches));
			if (macmatches)
			{
				*headerKeyUsed = ctx->init.server->firstreceiveheaderkey;
				return MR_E_SUCCESS;
			}
		}
	}

	FAILMSG(MR_E_NOTFOUND, "The message received had an unrecognized message authentication code.");
}

static mr_result deconstruct_message(_mr_ctx* ctx, uint8_t* message, uint32_t amount,
	uint8_t** payload, uint32_t* payloadsize,
	const uint8_t* headerkey, uint32_t headerkeysize,
	_mr_ratchet_state* step,
	bool usedNextKey)
{
	FAILIF(amount < MIN_MESSAGE_SIZE, MR_E_INVALIDSIZE, "A valid message is at least 16 bytes long");

	uint32_t headerIvOffset = amount - MAC_SIZE - HEADERIV_SIZE;

	// decrypt the header
	mr_aes_ctx aes = mr_aes_create(ctx);
	_mr_aesctr_ctx cipher;
	FAILIF(!aes, MR_E_NOMEM, "Could not allocate AES");
	mr_result result = MR_E_SUCCESS;
	_R(result, mr_aes_init(aes, headerkey, headerkeysize));
	_R(result, aesctr_init(&cipher, aes, message + headerIvOffset, HEADERIV_SIZE));
	_R(result, aesctr_process(&cipher, message, NONCE_SIZE, message, NONCE_SIZE));
	LOGD("headerkey             ", headerkey, headerkeysize);
	LOGD("headeriv              ", message + headerIvOffset, HEADERIV_SIZE);

	// decrypt ecdh if needed
	bool hasEcdh = message[0] & 0b10000000;

	// clear the ecdh bit
	message[0] = message[0] & 0b01111111;

	uint32_t ecdhOffset = NONCE_SIZE;
	uint32_t payloadOffset = NONCE_SIZE + (hasEcdh ? ECNUM_SIZE : 0);
	uint32_t payloadSize = amount - payloadOffset - MAC_SIZE;
	LOGD("[nonce]               ", message, NONCE_SIZE);

	if (hasEcdh)
	{
		LOGD("[ecdh]                ", message + NONCE_SIZE, ECNUM_SIZE);
		_R(result, aesctr_process(&cipher, message + NONCE_SIZE, ECNUM_SIZE, message + NONCE_SIZE, ECNUM_SIZE));
		LOGD("[ecdh]                ", message + NONCE_SIZE, ECNUM_SIZE);
	}
	mr_aes_destroy(aes);
	aes = 0;
	_C(result);


	// get the nonce
	uint32_t nonce = be_unpacku32(message);

	// process ecdh if needed
	_mr_ratchet_state* _step = 0;
	if (hasEcdh)
	{
		_C(mr_allocate(ctx, sizeof(_mr_ratchet_state), (void**)&_step));
		memset(_step, 0, sizeof(_mr_ratchet_state));

		if (!step)
		{
			// an override header key was used.
			// this means we have to initialize the ratchet
			FAILIF(ctx->config.is_client, MR_E_INVALIDOP, "Only the server can initialize a ratchet using an override header key");
			FAILIF(!ctx->init.server, MR_E_INVALIDOP, "The session is not in the state to process this message");

			_R(result, ratchet_initialize_server(ctx, _step,
				ctx->init.server->localratchetstep0,
				ctx->init.server->rootkey, KEY_SIZE,
				message + ecdhOffset, ECNUM_SIZE,
				ctx->init.server->localratchetstep1,
				ctx->init.server->firstreceiveheaderkey, KEY_SIZE,
				ctx->init.server->firstsendheaderkey, KEY_SIZE));
			if (result == 0)
			{
				// localratchetstep1 gets aliased by ratchet_initialize_server
				ctx->init.server->localratchetstep1 = 0;
				if (ctx->init.server->localratchetstep0)
				{
					mr_ecdh_destroy(ctx->init.server->localratchetstep0);
					ctx->init.server->localratchetstep0 = 0;
				}
			}
			_R(result, ratchet_add(ctx, _step));
			if (result == 0)
			{
				step = _step;
			}
			else
			{
				mr_free(ctx, _step);
				return result;
			}
		}
		else
		{
			if (usedNextKey)
			{
				// perform ecdh ratchet
				mr_ecdh_ctx newEcdh = mr_ecdh_create(ctx);
				if (!newEcdh) result = MR_E_NOMEM;
				_R(result, mr_ecdh_generate(newEcdh, 0, 0));

				_R(result, ratchet_ratchet(ctx, step,
					_step,
					message + ecdhOffset, ECNUM_SIZE,
					newEcdh));

				_R(result, ratchet_add(ctx, _step));
				if (result != MR_E_SUCCESS)
				{
					mr_ecdh_destroy(newEcdh);
					if (_step && _step->num) ratchet_destroy(ctx, _step->num);
				}
				_C(result);
				step = _step;
			}
		}

		_C(result);
	}

	if (!step)
	{
		// An override header key was used but the message did not contain ECDH parameters
		FAILMSG(MR_E_INVALIDOP, "An override header key was used but the message did not contain ECDH parameters");
	}

	// get the inner payload key from the receive chain
	uint8_t payloadKey[MSG_KEY_SIZE];
	_C(chain_ratchetforreceiving(ctx, &step->receivingchain, nonce, payloadKey, sizeof(payloadKey)));

	if (_step)
	{
		mr_free(ctx, _step);
	}

	// decrypt the payload
	_C(crypt(ctx, message + payloadOffset, payloadSize, payloadKey, MSG_KEY_SIZE, message, NONCE_SIZE));
	*payload = message + payloadOffset;
	*payloadsize = payloadSize;

	LOGD("[payload]             ", message + payloadOffset, payloadSize);

	return MR_E_SUCCESS;
}

static mr_result process_initialization(_mr_ctx* ctx, uint8_t* message, uint32_t amount, uint32_t spaceavail,
	const uint8_t* headerkey, uint32_t headerkeysize,
	_mr_ratchet_state* step)
{
	if (ctx->config.is_client)
	{
		if (!amount)
		{
			if (!ctx->init.client)
			{
				_C(mr_allocate(ctx, sizeof(_mr_initialization_state_client), (void**)&ctx->init.client));
			}
			else
			{
				if (ctx->init.client->localecdhforinit)
				{
					mr_ecdh_destroy(ctx->init.client->localecdhforinit);
				}
			}

			// reset client state
			ctx->init.initialized = false;

			memset(ctx->init.client, 0, sizeof(_mr_initialization_state_client));
			ratchet_destroy_all(ctx);
			memset(ctx->ratchets, 0, sizeof(ctx->ratchets));

			// step 1: send first init request from client
			_C(send_initialization_request(ctx, message, spaceavail));
			return MR_E_SENDBACK;
		}
		else
		{
			if (headerkey == ctx->config.applicationKey)
			{
				if (!ctx->ratchets[0].num)
				{
					// step 2: init response from server
					_C(receive_initialization_response(ctx, message, amount));
					_C(send_first_client_message(ctx, message, spaceavail));
					return MR_E_SENDBACK;
				}
				else
				{
					FAILMSG(MR_E_INVALIDOP, "Received an unexpected or duplicate response from the server");
				}
			}
			else if (step)
			{
				// step 3: receive first message from server
				_C(receive_first_server_response(ctx, message, amount, headerkey, headerkeysize, step));

				// initialization complete
				if (ctx->init.client->localecdhforinit)
				{
					mr_ecdh_destroy(ctx->init.client->localecdhforinit);
				}
				mr_free(ctx, ctx->init.client);
				ctx->init.client = 0;
				ctx->init.initialized = true;

				return MR_E_SUCCESS;
			}
		}
	}
	else
	{
		if (!amount)
		{
			FAILMSG(MR_E_INVALIDOP, "The server cannot initiate initialization");
		}
		else if (headerkey == ctx->config.applicationKey)
		{
			// step 1: client init request
			uint8_t* initialization_nonce;
			uint32_t initialization_nonce_size;
			uint8_t* remote_ecdh_for_init;
			uint32_t remote_ecdh_for_init_size;
			_C(receive_initialization_request(ctx, message, amount,
				&initialization_nonce, &initialization_nonce_size,
				&remote_ecdh_for_init, &remote_ecdh_for_init_size));
			_C(send_initialization_response(ctx,
				initialization_nonce, initialization_nonce_size,
				remote_ecdh_for_init, remote_ecdh_for_init_size,
				message, spaceavail));

			ctx->init.initialized = false;

			// reset ratchets if this is a reinitialization
			ratchet_destroy_all(ctx);

			return MR_E_SENDBACK;
		}
		else if (ctx->init.server && headerkey == ctx->init.server->firstreceiveheaderkey)
		{
			// step 2: first message from client
			_C(receive_first_client_message(ctx, message, amount));
			_C(send_first_server_response(ctx, message, spaceavail));
			ctx->init.initialized = true;
			return MR_E_SENDBACK;
		}
	}

	FAILMSG(MR_E_INVALIDOP, "Unexpected message received during initialization");
}

mr_result mr_ctx_initiate_initialization(mr_ctx _ctx, uint8_t* message, uint32_t spaceavailable, bool force)
{
	_mr_ctx* ctx = _ctx;
	if (ctx->init.initialized && !force)
	{
		FAILMSG(MR_E_INVALIDOP, "The context is already initialized. To re-initialize use the force argument");
	}

	if (!ctx->config.is_client)
	{
		FAILMSG(MR_E_INVALIDOP, "Only a client can initiate initialization");
	}

	return process_initialization(ctx, message, 0, spaceavailable, 0, 0, 0);
}

mr_result mr_ctx_receive(mr_ctx _ctx, uint8_t* message, uint32_t messagesize, uint32_t spaceavailable, uint8_t** payload, uint32_t* payloadsize)
{
	_mr_ctx* ctx = _ctx;
	FAILIF(!ctx, MR_E_INVALIDARG, "Context must be provided");
	FAILIF(!message, MR_E_INVALIDARG, "Message must be provided");
	FAILIF(messagesize < MIN_MESSAGE_SIZE, MR_E_INVALIDARG, "The message size must be at least 32 bytes");
	FAILIF(spaceavailable < MIN_MESSAGE_SIZE, MR_E_INVALIDARG, "The space available must be at least 32 bytes");
	FAILIF(spaceavailable < messagesize, MR_E_INVALIDARG, "The space available must be at least as much as the message size");

	if (ctx->config.is_client) LOG("\n\n====CLIENT RECEIVE");
	else LOG("\n\n====SERVER RECEIVE");

	// check the MAC and get info regarding the message header
	uint8_t* headerkeyused = 0;
	_mr_ratchet_state* stepused = 0;
	bool usednextheaderkey = false;
	_C(interpret_mac(ctx, message, messagesize,
		&headerkeyused,
		&stepused,
		&usednextheaderkey));

	if (!headerkeyused)
	{
		FAILMSG(MR_E_INVALIDOP, "Could not identify the header key used to send a message");
	}
	else if (headerkeyused == ctx->config.applicationKey || !ctx->init.initialized)
	{
		if (!ctx->init.server)
		{
			_C(mr_allocate(ctx, sizeof(_mr_initialization_state_server), (void**)&ctx->init.server));
			memset(ctx->init.server, 0, sizeof(_mr_initialization_state_server));
		}

		// if the application key was used this is an initialization message
		mr_result result = process_initialization(ctx,
			message, messagesize, spaceavailable,
			headerkeyused, KEY_SIZE,
			stepused);

		// assign payload and payloadsize variables if needed
		if (result == MR_E_SENDBACK)
		{
			if (payload)
			{
				*payload = message;
			}

			if (payloadsize)
			{
				*payloadsize = spaceavailable;
			}
		}
		else
		{
			if (payload)
			{
				*payload = 0;
			}

			if (payloadsize)
			{
				*payloadsize = 0;
			}
		}

		return result;
	}
	else if (stepused)
	{
		_C(deconstruct_message(ctx, message, messagesize, payload, payloadsize, headerkeyused, KEY_SIZE, stepused, usednextheaderkey));

		// received first normal message, free init state
		if (!ctx->config.is_client && ctx->init.server)
		{
			if (ctx->init.server->localratchetstep0)
			{
				mr_ecdh_destroy(ctx->init.server->localratchetstep0);
			}
			if (ctx->init.server->localratchetstep1)
			{
				mr_ecdh_destroy(ctx->init.server->localratchetstep1);
			}
			mr_free(ctx, ctx->init.server);
			ctx->init.server = 0;
		}
	}
	else
	{
		FAILMSG(MR_E_INVALIDOP, "Could not identify the ECDH step used to send a message");
	}

	return MR_E_SUCCESS;
}

mr_result mr_ctx_send(mr_ctx _ctx, uint8_t* payload, uint32_t payloadsize, uint32_t spaceavailable)
{
	_mr_ctx* ctx = _ctx;
	FAILIF(!ctx, MR_E_INVALIDARG, "The context must be provided");
	FAILIF(!payload, MR_E_INVALIDARG, "The payload must be provided");
	FAILIF(!ctx->init.initialized, MR_E_INVALIDOP, "The session has not been initialized and cannot send yet");
	FAILIF(spaceavailable - payloadsize < OVERHEAD_WITHOUT_ECDH, MR_E_INVALIDSIZE, "The amount of space available must be at least 16 bytes.");

	if (ctx->config.is_client) LOG("\n\n====CLIENT SEND");
	else LOG("\n\n====SERVER SEND");

	bool canIncludeEcdh = spaceavailable - payloadsize >= OVERHEAD_WITH_ECDH;

	_mr_ratchet_state* step;
	if (canIncludeEcdh)
	{
		_C(ratchet_getlast(ctx, &step));
	}
	else
	{
		_C(ratchet_getsecondtolast(ctx, &step));
	}

	_C(construct_message(ctx, payload, payloadsize, spaceavailable, canIncludeEcdh, step));

	return MR_E_SUCCESS;
}

void mr_ctx_destroy(mr_ctx _ctx)
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

		if (ctx->identity && ctx->owns_identity)
		{
			mr_ecdsa_destroy(ctx->identity);
			ctx->identity = 0;
		}

		ratchet_destroy_all(ctx);

		if (ctx->config.is_client && ctx->init.client)
		{
			if (ctx->init.client->localecdhforinit)
			{
				mr_ecdh_destroy(ctx->init.client->localecdhforinit);
			}

			mr_free(ctx, ctx->init.client);
			ctx->init.client = 0;
		}

		if (!ctx->config.is_client && ctx->init.server)
		{
			if (ctx->init.server->localratchetstep0)
			{
				mr_ecdh_destroy(ctx->init.server->localratchetstep0);
			}
			if (ctx->init.server->localratchetstep1)
			{
				mr_ecdh_destroy(ctx->init.server->localratchetstep1);
			}

			mr_free(ctx, ctx->init.server);
			ctx->init.server = 0;
		}

		memset(ctx, 0, sizeof(_mr_ctx));
		mr_free(ctx, ctx);
	}
}