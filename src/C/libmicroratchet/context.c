#include "pch.h"
#include "microratchet.h"
#include "internal.h"

// forward
static mr_result_t construct_message(_mr_ctx* ctx, uint8_t* message, uint32_t amount, uint32_t spaceavail, bool includeecdh, _mr_ratchet_state* step);
static mr_result_t deconstruct_message(_mr_ctx* ctx, uint8_t* message, uint32_t amount, uint8_t** payload, uint32_t* payloadsize, const uint8_t* headerkey, uint32_t headerkeysize, _mr_ratchet_state* step, bool usedNextKey);

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

static mr_result_t computemac(_mr_ctx* ctx, uint8_t* data, uint32_t datasize, const uint8_t* key, uint32_t keysize, const uint8_t* iv, uint32_t ivsize)
{
	FAILIF(!ctx || !data || !key || !iv, E_INVALIDARGUMENT, "Some of the required arguments were null")
	FAILIF(keysize != KEY_SIZE, E_INVALIDSIZE, "The key size was invalid")
	FAILIF(ivsize < NONCE_SIZE, E_INVALIDSIZE, "The nonce was too small")
	FAILIF(datasize < MAC_SIZE + 1, E_INVALIDSIZE, "The data size was too small. Must be at least the size of a MAC plus one byte")

	mr_poly_ctx mac = mr_poly_create(ctx);
	FAILIF(!mac, E_NOMEM, "Could not allocate a POLY1305 instance")
	mr_result_t result = E_SUCCESS;
	_R(result, mr_poly_init(mac, key, keysize, iv, ivsize));
	_R(result, mr_poly_process(mac, data, datasize - MAC_SIZE));
	_R(result, mr_poly_compute(mac, data + datasize - MAC_SIZE, MAC_SIZE));
	mr_poly_destroy(mac);
	_C(result);

	LOGD("mac iv                ", iv, ivsize);
	LOGD("mac key               ", key, keysize);
	LOGD("mac computed          ", data + datasize - MAC_SIZE, MAC_SIZE);
	return E_SUCCESS;
}

static mr_result_t verifymac(_mr_ctx* ctx, const uint8_t* data, uint32_t datasize, const uint8_t* key, uint32_t keysize, const uint8_t* iv, uint32_t ivsize, bool* result)
{
	FAILIF(!ctx || !data || !key || !iv || !result, E_INVALIDARGUMENT, "Some of the required arguments were null")
	FAILIF(keysize != KEY_SIZE, E_INVALIDSIZE, "The key size was invalid")
	FAILIF(ivsize < NONCE_SIZE, E_INVALIDSIZE, "The nonce was too small")
	FAILIF(datasize < MAC_SIZE + 1, E_INVALIDSIZE, "The data size was too small. Must be at least the size of a MAC plus one byte")

	*result = false;

	uint8_t computedmac[MAC_SIZE] = { 0 };
	mr_poly_ctx mac = mr_poly_create(ctx);
	FAILIF(!mac, E_NOMEM, "Could not allocate a POLY1305 instance")
	mr_result_t rr = E_SUCCESS;
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
	return E_SUCCESS;
}

static mr_result_t digest(_mr_ctx* ctx, const uint8_t* data, uint32_t datasize, uint8_t* digest, uint32_t digestsize)
{
	FAILIF(!ctx || !data || !digest, E_INVALIDARGUMENT, "Some of the required arguments were null")
	FAILIF(digestsize < DIGEST_SIZE, E_INVALIDSIZE, "The output space was smaller than the digest size")

	_C(mr_sha_init(ctx->sha_ctx));
	_C(mr_sha_process(ctx->sha_ctx, data, datasize));
	_C(mr_sha_compute(ctx->sha_ctx, digest, digestsize));
	return E_SUCCESS;
}

static mr_result_t sign(_mr_ctx* ctx, uint8_t* data, uint32_t datasize, mr_ecdsa_ctx signer)
{
	FAILIF(!ctx || !data || !signer, E_INVALIDARGUMENT, "Some of the required arguments were null")
	FAILIF(datasize < SIGNATURE_SIZE + 1, E_INVALIDSIZE, "The data size was too small. Must be at least the size of a signature and one byte extra")

	uint8_t sha[DIGEST_SIZE];
	uint32_t sigresult = 0;
	_C(digest(ctx, data, datasize - SIGNATURE_SIZE, sha, sizeof(sha)));
	_C(mr_ecdsa_sign(signer, sha, DIGEST_SIZE, data + datasize - SIGNATURE_SIZE, SIGNATURE_SIZE));
	LOGD("signature hash        ", sha, DIGEST_SIZE);
	LOGD("signature             ", data + datasize - SIGNATURE_SIZE, SIGNATURE_SIZE);
	return E_SUCCESS;
}

static mr_result_t verifysig(_mr_ctx* ctx, const uint8_t* data, uint32_t datasize, const uint8_t* pubkey, uint32_t pubkeysize, bool* result)
{
	FAILIF(!ctx || !data || !pubkey || !result, E_INVALIDARGUMENT, "Some of the required arguments were null")
	FAILIF(datasize < SIGNATURE_SIZE + 1, E_INVALIDSIZE, "The data size was too small. Must be at least the size of a signature and one byte extra")

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
	return E_SUCCESS;
}

static mr_result_t crypt(_mr_ctx* ctx, uint8_t* data, uint32_t datasize, const uint8_t* key, uint32_t keysize, const uint8_t* iv, uint32_t ivsize)
{
	FAILIF(!ctx || !data || !key || !iv, E_INVALIDARGUMENT, "Some of the required arguments were null")
	FAILIF(datasize < 1, E_INVALIDSIZE, "At least one byte of data must be specified")
	FAILIF(keysize != KEY_SIZE && keysize != MSG_KEY_SIZE, E_INVALIDSIZE, "The key size was invalid")
	FAILIF(ivsize < NONCE_SIZE, E_INVALIDSIZE, "The IV size was to small")

	LOGD("crypt with iv         ", iv, ivsize);
	LOGD("crypt with key        ", key, keysize);

	mr_aes_ctx aes = mr_aes_create(ctx);
	_mr_aesctr_ctx cipher;
	FAILIF(!aes, E_NOMEM, "Could not allocate AES")
	mr_result_t result = E_SUCCESS;
	_R(result, mr_aes_init(aes, key, keysize));
	_R(result, aesctr_init(&cipher, aes, iv, ivsize));
	_R(result, aesctr_process(&cipher, data, datasize, data, datasize));
	mr_aes_destroy(aes);
	_C(result);
	return E_SUCCESS;
}

mr_ctx mrclient_create(const mr_config* config)
{
	if (!config) return 0;

	_mr_ctx* ctx;
	int r = mr_allocate(0, sizeof(_mr_ctx), &ctx);
	if (r != E_SUCCESS || !ctx) return 0;

	*ctx = (_mr_ctx){
		*config,
		mr_sha_create(ctx),
		mr_rng_create(ctx)
	};

	return ctx;
}

mr_result_t mrclient_set_identity(mr_ctx _ctx, mr_ecdsa_ctx identity)
{
	_mr_ctx* ctx = (_mr_ctx*)_ctx;
	FAILIF(!ctx, E_INVALIDARGUMENT, "The context given was null")
	FAILIF(!identity, E_INVALIDARGUMENT, "The identity given was null")
	
	ctx->identity = identity;
	return E_SUCCESS;
}

static mr_result_t send_initialization_request(_mr_ctx* ctx, uint8_t* output, uint32_t spaceavail)
{
	FAILIF(!ctx || !output, E_INVALIDARGUMENT, "Some of the required parameters were null")
	FAILIF(!ctx->config.is_client, E_INVALIDOP, "Only the client can send an initialization request")
	FAILIF(spaceavail < INIT_REQ_MSG_SIZE, E_INVALIDSIZE, "The space avaialble was less than the minimum init request message size")
	FAILIF(!ctx->identity, E_INVALIDOP, "The session does not have an identity")
	FAILIF(!ctx->init.client, E_INVALIDOP, "Client initialization state is null")

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
	uint32_t signatureOffset = spaceavail - MAC_SIZE - SIGNATURE_SIZE;
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

	return E_SUCCESS;
}

static mr_result_t receive_initialization_request(_mr_ctx* ctx, uint8_t* data, uint32_t amount,
	uint8_t** initializationnonce, uint32_t* initializationnoncesize,
	uint8_t** remoteecdhforinit, uint32_t* remoteecdhforinitsize)
{
	FAILIF(!ctx || !data || !initializationnonce ||
		!initializationnoncesize || !remoteecdhforinit ||
		!remoteecdhforinitsize, E_INVALIDARGUMENT, "Some of the required arguments were null");
	FAILIF(amount < INIT_REQ_MSG_SIZE, E_INVALIDSIZE, "The space amount of data was less than the minimum init request message size");
	FAILIF(ctx->config.is_client, E_INVALIDOP, "Only the server can receive an init request");
	FAILIF(!ctx->identity, E_INVALIDOP, "The session does not have an identity");
	FAILIF(!ctx->init.server, E_INVALIDOP, "Server initialization state is null")

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
	uint32_t signatureOffset = macOffset - SIGNATURE_SIZE;
	uint32_t remoteEcdhOffset = INITIALIZATION_NONCE_SIZE + ECNUM_SIZE;
	uint32_t clientPublicKeyOffset = INITIALIZATION_NONCE_SIZE;

	if (!allzeroes(ctx->init.server->clientpublickey, ECNUM_SIZE))
	{
		if (memcmp(ctx->init.server->clientpublickey, data + clientPublicKeyOffset, ECNUM_SIZE) != 0)
		{
			return E_INVALIDOP;
		}
		else
		{
			// the client wants to reinitialize. Reset state.
			if (ctx->init.server) mr_free(ctx, ctx->init.server);
			ctx->init = (_mr_initialization_state){ 0 };
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

	return E_SUCCESS;
}

static mr_result_t send_initialization_response(_mr_ctx* ctx,
	uint8_t* initializationnonce, uint32_t initializationnoncesize,
	uint8_t* remoteecdhforinit, uint32_t remoteecdhforinitsize,
	uint8_t* output, uint32_t spaceavail)
{
	FAILIF(!ctx || !initializationnonce || !remoteecdhforinit || !output, E_INVALIDARGUMENT, "Some of the required parameters were null");
	FAILIF(ctx->config.is_client, E_INVALIDOP, "Only the server can send an initialization response");
	FAILIF(initializationnoncesize != INITIALIZATION_NONCE_SIZE, E_INVALIDSIZE, "The initialization nonce size was invalid")
	FAILIF(remoteecdhforinitsize != ECNUM_SIZE, E_INVALIDSIZE, "The ECDH public key was of an incorrect size")
	FAILIF(spaceavail < INIT_RES_MSG_SIZE, E_INVALIDSIZE, "The amount of space available is less than the minimum space required for an initialization response")
	FAILIF(!ctx->init.server, E_INVALIDOP, "Server initialization state is null")

	LOG("--send_initialization_response");

	// store the passed in parms because we're going to overwrite the buffer
	uint8_t tmp1[INITIALIZATION_NONCE_SIZE];
	uint8_t tmp2[ECNUM_SIZE];
	memcpy(tmp1, initializationnonce, INITIALIZATION_NONCE_SIZE);
	memcpy(tmp2, remoteecdhforinit, ECNUM_SIZE);
	initializationnonce = tmp1;
	remoteecdhforinit = tmp2;

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
	FAILIF(!rootPreEcdh, E_NOMEM, "Could not allocate ECDH parameters")
	mr_result_t result = E_SUCCESS;
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
	ctx->init.server->localratchetstep0 = mr_ecdh_create(ctx);
	FAILIF(!ctx->init.server->localratchetstep0, E_NOMEM, "Could not allocate ECDH parameters")
	_C(mr_ecdh_generate(ctx->init.server->localratchetstep0, rre0, sizeof(rre0)));
	LOGD("rre0                  ", rre0, ECNUM_SIZE);
	uint8_t rre1[ECNUM_SIZE];
	ctx->init.server->localratchetstep1 = mr_ecdh_create(ctx);
	FAILIF(!ctx->init.server->localratchetstep1, E_NOMEM, "Could not allocate ECDH parameters")
	_C(mr_ecdh_generate(ctx->init.server->localratchetstep1, rre1, sizeof(rre1)));
	LOGD("rre1                  ", rre1, ECNUM_SIZE);

	uint32_t minimumMessageSize = INITIALIZATION_NONCE_SIZE * 2 + ECNUM_SIZE * 6 + MAC_SIZE;
	uint32_t macOffset = spaceavail - MAC_SIZE;
	uint32_t entireMessageWithoutMacOrSignatureSize = macOffset - SIGNATURE_SIZE;
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

	return E_SUCCESS;
}

static mr_result_t receive_initialization_response(_mr_ctx* ctx,
	uint8_t* data, uint32_t amount)
{
	FAILIF(!ctx || !data, E_INVALIDARGUMENT, "Some of the required arguments were null")
	FAILIF(!ctx->config.is_client, E_INVALIDOP, "Only the client can receive an initialization response")
	FAILIF(amount < INIT_RES_MSG_SIZE, E_INVALIDARGUMENT, "The message was smaller than the minimum init response message size")
	FAILIF(!ctx->init.client, E_INVALIDOP, "Client initialization state is null")

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
		return E_INVALIDOP;
	}

	// verify the signature
	bool sigvalid = false;
	_C(verifysig(ctx,
		data, headerSize + payloadSize,
		payload + INITIALIZATION_NONCE_SIZE, ECNUM_SIZE,
		&sigvalid));
	if (!sigvalid)
	{
		return E_INVALIDOP;
	}

	// store the nonce we got from the server
	memcpy(ctx->init.client->initializationnonce, data, INITIALIZATION_NONCE_SIZE);
	LOGD("server init nonce     ", data, INITIALIZATION_NONCE_SIZE);

	// we now have enough information to construct our double ratchet
	mr_result_t result = E_SUCCESS;
	uint8_t localStep0Pub[ECNUM_SIZE];
	mr_ecdh_ctx localStep0 = mr_ecdh_create(ctx);
	FAILIF(!localStep0, E_NOMEM, "Could not allocate ECDH parameters")
	_R(result, mr_ecdh_generate(localStep0, localStep0Pub, sizeof(localStep0Pub)));
	LOGD("local step0 pub       ", localStep0Pub, ECNUM_SIZE);
	uint8_t localStep1Pub[ECNUM_SIZE];
	mr_ecdh_ctx localStep1 = mr_ecdh_create(ctx);
	FAILIF(!localStep1, E_NOMEM, "Could not allocate ECDH parameters")
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
	_mr_ratchet_state ratchet0 = { 0 };
	_mr_ratchet_state ratchet1 = { 0 };
	_R(result, ratchet_initialize_client(ctx, &ratchet0, &ratchet1,
		rootKey, KEY_SIZE,
		remoteRatchetEcdh0, ECNUM_SIZE,
		remoteRatchetEcdh1, ECNUM_SIZE,
		localStep0,
		receiveHeaderKey, KEY_SIZE,
		sendHeaderKey, KEY_SIZE,
		localStep1));
	_R(result, ratchet_add(ctx, &ratchet0));
	_R(result, ratchet_add(ctx, &ratchet1));

	if (result != E_SUCCESS)
	{
		if (localStep0) mr_ecdh_destroy(localStep0);
		if (localStep1) mr_ecdh_destroy(localStep1);
		if (ratchet0.num) ratchet_destroy(ctx, ratchet0.num);
		if (ratchet1.num) ratchet_destroy(ctx, ratchet1.num);
	}
	_C(result);

	return E_SUCCESS;
}

static mr_result_t send_first_client_message(_mr_ctx* ctx, uint8_t* output, uint32_t spaceavail)
{
	FAILIF(!ctx->config.is_client, E_INVALIDOP, "Only the client can send the first message")
	FAILIF(!ctx->init.client, E_INVALIDOP, "Client initialization state is null")

	_mr_ratchet_state* secondToLast;
	_C(ratchet_getsecondtolast(ctx, &secondToLast));

	memcpy(output, ctx->init.client->initializationnonce, INITIALIZATION_NONCE_SIZE);

	return construct_message(ctx, output, INITIALIZATION_NONCE_SIZE, spaceavail, true, secondToLast);
}

static mr_result_t receive_first_client_message(_mr_ctx* ctx, uint8_t* data, uint32_t amount)
{
	FAILIF(ctx->config.is_client, E_INVALIDOP, "Only the server can receive the first client message")
	FAILIF(!ctx->init.server, E_INVALIDOP, "Server initialization state is null")

	uint8_t* payload = 0;
	uint32_t payloadSize = 0;
	_C(deconstruct_message(ctx,
		data, amount,
		&payload, &payloadSize,
		ctx->init.server->firstreceiveheaderkey, KEY_SIZE,
		0, false));

	if (payloadSize < INITIALIZATION_NONCE_SIZE || memcmp(payload, ctx->init.server->nextinitializationnonce, INITIALIZATION_NONCE_SIZE) != 0)
	{
		return E_INVALIDOP;
	}

	return E_SUCCESS;
}

static mr_result_t send_first_server_response(_mr_ctx* ctx, uint8_t* output, uint32_t spaceavail)
{
	FAILIF(ctx->config.is_client, E_INVALIDOP, "Only the server can send the first server response")
	FAILIF(!ctx->init.server, E_INVALIDOP, "Server initialization state is null")

	memcpy(output, ctx->init.server->nextinitializationnonce, INITIALIZATION_NONCE_SIZE);
	_mr_ratchet_state *laststep;
	_C(ratchet_getlast(ctx, &laststep));
	_C(construct_message(ctx, output, INITIALIZATION_NONCE_SIZE, spaceavail, false, laststep));

	return E_SUCCESS;
}

static mr_result_t receive_first_server_response(_mr_ctx* ctx, uint8_t* data, uint32_t amount,
	const uint8_t* headerkey, uint32_t headerkeysize,
	_mr_ratchet_state* step)
{
	FAILIF(!ctx->config.is_client, E_INVALIDOP, "Only the client can receive the first server response")
	FAILIF(!ctx->init.client, E_INVALIDOP, "Client initialization state is null")


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
		return E_INVALIDOP;
	}

	return E_SUCCESS;
}

static mr_result_t construct_message(_mr_ctx* ctx, uint8_t* message, uint32_t amount, uint32_t spaceavail,
	bool includeecdh,
	_mr_ratchet_state* step)
{
	FAILIF(!ctx || !message, E_INVALIDARGUMENT, "Some of the required arguments were null")
	FAILIF(includeecdh && spaceavail < MIN_MESSAGE_SIZE_WITH_ECDH, E_INVALIDSIZE, "When ECDH is included in the total message will be at least 64 bytes")
	FAILIF(!includeecdh && spaceavail < MIN_MESSAGE_SIZE, E_INVALIDSIZE, "When ECDH is not included the total message will be at least 32 bytes")
	FAILIF(includeecdh && spaceavail < amount + OVERHEAD_WITH_ECDH, E_INVALIDSIZE, "When ECDH is included in the message there must be at least 48 bytes of extra space")
	FAILIF(!includeecdh && spaceavail < amount + OVERHEAD_WITHOUT_ECDH, E_INVALIDSIZE, "When ECDH is not included there must be at least 16 bytes of extra space")

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
		return E_INVALIDOP;
	}

	// calculate some sizes
	uint32_t headersize = NONCE_SIZE + (includeecdh ? ECNUM_SIZE : 0);
	uint32_t overhead = headersize + MAC_SIZE;
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

	return E_SUCCESS;
}

static mr_result_t interpret_mac(_mr_ctx* ctx, const uint8_t* message, uint32_t amount,
	const uint8_t** headerKeyUsed, _mr_ratchet_state** stepUsed, bool* usedNextHeaderKey)
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
					return E_SUCCESS;
				}
				else if (!allzeroes(ctx->ratchets[i].nextreceiveheaderkey, KEY_SIZE))
				{
					_C(verifymac(ctx, message, amount, ctx->ratchets[i].nextreceiveheaderkey, KEY_SIZE, message, MACIV_SIZE, &macmatches));
					if (macmatches)
					{
						*headerKeyUsed = ctx->ratchets[i].nextreceiveheaderkey;
						*stepUsed = &ctx->ratchets[i];
						*usedNextHeaderKey = true;
						return E_SUCCESS;
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
		return E_SUCCESS;
	}
	else if (!ctx->config.is_client)
	{
		if (!ctx->init.initialized && ctx->ratchets[0].num == 0 && ctx->init.server && !allzeroes(ctx->init.server->firstreceiveheaderkey, KEY_SIZE))
		{
			_C(verifymac(ctx, message, amount, ctx->init.server->firstreceiveheaderkey, KEY_SIZE, message, MACIV_SIZE, &macmatches));
			if (macmatches)
			{
				*headerKeyUsed = ctx->init.server->firstreceiveheaderkey;
				return E_SUCCESS;
			}
		}
	}
	

	return E_NOTFOUND;
}

static mr_result_t deconstruct_message(_mr_ctx* ctx, uint8_t* message, uint32_t amount,
	uint8_t** payload, uint32_t* payloadsize,
	const uint8_t* headerkey, uint32_t headerkeysize,
	_mr_ratchet_state* step,
	bool usedNextKey)
{
	FAILIF(amount < MIN_MESSAGE_SIZE, E_INVALIDSIZE, "A valid message is at least 16 bytes long")

	uint32_t headerIvOffset = amount - MAC_SIZE - HEADERIV_SIZE;

	// decrypt the header
	mr_aes_ctx aes = mr_aes_create(ctx);
	_mr_aesctr_ctx cipher;
	FAILIF(!aes, E_NOMEM, "Could not allocate AES")
	mr_result_t result = E_SUCCESS;
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
	_mr_ratchet_state _step = {0};
	if (hasEcdh)
	{
		if (!step)
		{
			// an override header key was used.
			// this means we have to initialize the ratchet
			FAILIF(ctx->config.is_client, E_INVALIDOP, "Only the server can initialize a ratchet using an override header key");
			FAILIF(!ctx->init.server, E_INVALIDOP, "The session is not in the state to process this message");

			_C(ratchet_initialize_server(ctx, &_step,
				ctx->init.server->localratchetstep0,
				ctx->init.server->rootkey, KEY_SIZE,
				message + ecdhOffset, ECNUM_SIZE,
				ctx->init.server->localratchetstep1,
				ctx->init.server->firstreceiveheaderkey, KEY_SIZE,
				ctx->init.server->firstsendheaderkey, KEY_SIZE));
			_C(ratchet_add(ctx, &_step));
			mr_ecdh_destroy(ctx->init.server->localratchetstep0);
			ctx->init.server->localratchetstep0 = 0;
			ctx->init.server->localratchetstep1 = 0;
			step = &_step;
		}
		else
		{
			if (usedNextKey)
			{
				// perform ecdh ratchet
				mr_ecdh_ctx newEcdh = mr_ecdh_create(ctx);
				FAILIF(!newEcdh, E_NOMEM, "Could not allocate ECDH paramters")
				mr_result_t result = E_SUCCESS;
				_R(result, mr_ecdh_generate(newEcdh, 0, 0));

				_R(result, ratchet_ratchet(ctx, step,
					&_step,
					message + ecdhOffset, ECNUM_SIZE,
					newEcdh));

				_R(result, ratchet_add(ctx, &_step));
				if (result != E_SUCCESS)
				{
					mr_ecdh_destroy(newEcdh);
					if (_step.num) ratchet_destroy(ctx, _step.num);
				}
				_C(result);
				step = &_step;
			}
		}
	}

	if (!step)
	{
		// An override header key was used but the message did not contain ECDH parameters
		return E_INVALIDOP;
	}

	// get the inner payload key from the receive chain
	uint8_t payloadKey[MSG_KEY_SIZE];
	_C(chain_ratchetforreceiving(ctx, &step->receivingchain, nonce, payloadKey, sizeof(payloadKey)));

	// decrypt the payload
	_C(crypt(ctx, message + payloadOffset, payloadSize, payloadKey, MSG_KEY_SIZE, message, NONCE_SIZE));
	*payload = message + payloadOffset;
	*payloadsize = payloadSize;

	LOGD("[payload]             ", message + payloadOffset, payloadSize);
	
	return E_SUCCESS;
}

static mr_result_t process_initialization(_mr_ctx* ctx, uint8_t* message, uint32_t amount, uint32_t spaceavail,
	const uint8_t* headerkey, uint32_t headerkeysize,
	_mr_ratchet_state* step)
{
	if (ctx->config.is_client)
	{
		if (!amount)
		{
			if (!ctx->init.client)
			{
				_C(mr_allocate(ctx, sizeof(_mr_initialization_state_client), &ctx->init.client));
				*ctx->init.client = (_mr_initialization_state_client){ 0 };
			}

			// step 1: send first init request from client
			_C(send_initialization_request(ctx, message, spaceavail));
			return E_SENDBACK;
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
					return E_SENDBACK;
				}
				else
				{
					return E_INVALIDOP;
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

				return E_SUCCESS;
			}
		}
	}
	else
	{
		if (!amount)
		{
			return E_INVALIDOP;
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
			return E_SENDBACK;
		}
		else if (ctx->init.server && headerkey == ctx->init.server->firstreceiveheaderkey)
		{
			// step 2: first message from client
			_C(receive_first_client_message(ctx, message, amount));
			_C(send_first_server_response(ctx, message, spaceavail));
			ctx->init.initialized = true;
			return E_SENDBACK;
		}
	}

	return E_INVALIDOP;
}

mr_result_t mrclient_initiate_initialization(mr_ctx _ctx, uint8_t* message, uint32_t spaceavailable, bool force)
{
	_mr_ctx* ctx = _ctx;
	if (ctx->init.initialized && !force)
	{
		return E_INVALIDOP;
	}

	if (!ctx->config.is_client)
	{
		return E_INVALIDOP;
	}

	return process_initialization(ctx, message, 0, spaceavailable, 0, 0, 0);
}

mr_result_t mrclient_receive(mr_ctx _ctx, uint8_t* message, uint32_t messagesize, uint32_t spaceavailable, uint8_t** payload, uint32_t* payloadsize)
{
	_mr_ctx* ctx = _ctx;
	FAILIF(!ctx, E_INVALIDARGUMENT, "Context must be provided")
	FAILIF(!message, E_INVALIDARGUMENT, "Message must be provided")
	FAILIF(messagesize < MIN_MESSAGE_SIZE, E_INVALIDARGUMENT, "The message size must be at least 32 bytes")
	FAILIF(spaceavailable < MIN_MESSAGE_SIZE, E_INVALIDARGUMENT, "The space available must be at least 32 bytes")
	FAILIF(spaceavailable < messagesize, E_INVALIDARGUMENT, "The space available must be at least as much as the message size")

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
		return E_INVALIDOP;
	}
	else if (headerkeyused == ctx->config.applicationKey || !ctx->init.initialized)
	{
		if (!ctx->init.server)
		{
			_C(mr_allocate(ctx, sizeof(_mr_initialization_state_server), &ctx->init.server));
			*ctx->init.server = (_mr_initialization_state_server){ 0 };
		}

		// if the application key was used this is an initialization message
		return process_initialization(ctx,
			message, messagesize, spaceavailable,
			headerkeyused, KEY_SIZE,
			stepused);
	}
	else if (stepused)
	{
		_C(deconstruct_message(ctx, message, messagesize, payload, payloadsize, headerkeyused, KEY_SIZE, stepused, usednextheaderkey));

		// received first normal message, free init state
		if (!ctx->config.is_client && ctx->init.server)
		{
			mr_free(ctx, ctx->init.server);
			ctx->init.server = 0;
		}
	}
	else
	{
		return E_INVALIDOP;
	}

	return E_SUCCESS;
}

mr_result_t mrclient_send(mr_ctx _ctx, uint8_t* payload, uint32_t payloadsize, uint32_t spaceavailable)
{
	_mr_ctx* ctx = _ctx;
	FAILIF(!ctx, E_INVALIDARGUMENT, "The context must be provided")
	FAILIF(!payload, E_INVALIDARGUMENT, "The payload must be provided")
	FAILIF(!ctx->init.initialized, E_INVALIDOP, "The session has not been initialized and cannot send yet")
	FAILIF(spaceavailable - payloadsize < OVERHEAD_WITHOUT_ECDH, E_INVALIDSIZE, "The amount of space available must be at least 16 bytes.")

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

	return E_SUCCESS;
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

		for (int i = 0; i < NUM_RATCHETS; i++)
		{
			if (ctx->ratchets[i].ecdhkey)
			{
				mr_ecdh_destroy(ctx->ratchets[i].ecdhkey);
			}
		}

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

		*ctx = (_mr_ctx){ 0 };
		mr_free(ctx, ctx);
	}
}