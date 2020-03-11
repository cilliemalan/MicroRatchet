#include "pch.h"
#include <microratchet.h>
#include <internal.h>
#include "support.h"

static bool is_empty_after(const void* data, uint32_t totalSize, uint32_t spaceUsed)
{
	EXPECT_LE(spaceUsed, totalSize);

	if (spaceUsed <= totalSize)
	{
		uint32_t spaceFree = totalSize - spaceUsed;
		const uint8_t* d = (const uint8_t*)data;
		d += spaceUsed;
		bool allZeroes = true;
		for (uint32_t i = 0; i < spaceFree; i++)
		{
			if (d[i])
			{
				allZeroes = false;
				break;
			}
		}

		return allZeroes;
	}

	return true;
}

static inline void compare_ecdh(mr_ecdh_ctx a, mr_ecdh_ctx b)
{
	EXPECT_TRUE((a != nullptr) == (b != nullptr));
	if (a && b)
	{
		uint8_t pa[ECNUM_SIZE];
		uint8_t pb[ECNUM_SIZE];
		EXPECT_EQ(MR_E_SUCCESS, mr_ecdh_getpublickey(a, pa, sizeof(pa)));
		EXPECT_EQ(MR_E_SUCCESS, mr_ecdh_getpublickey(b, pb, sizeof(pb)));
		EXPECT_BUFFEREQS(pa, pb);
	}
}

static void compare_states(mr_ctx _a, mr_ctx _b)
{
	_mr_ctx& a = *(_mr_ctx*)_a;
	_mr_ctx& b = *(_mr_ctx*)_b;

	EXPECT_EQ(a.config.is_client, b.config.is_client);
	EXPECT_EQ(a.init.initialized, b.init.initialized);
	if (!a.init.initialized && !b.init.initialized)
	{
		if (a.config.is_client)
		{
			_mr_initialization_state_client* ac = a.init.client;
			_mr_initialization_state_client* bc = b.init.client;
			EXPECT_TRUE((ac != nullptr) == (bc != nullptr));
			if (ac && bc)
			{
				EXPECT_BUFFEREQS(ac->initializationnonce, bc->initializationnonce);
				compare_ecdh(ac->localecdhforinit, bc->localecdhforinit);
			}
		}
		else
		{
			_mr_initialization_state_server* as = a.init.server;
			_mr_initialization_state_server* bs = b.init.server;
			EXPECT_TRUE((as != nullptr) == (bs != nullptr));
			if (as && bs)
			{
				EXPECT_BUFFEREQS(as->clientpublickey, bs->clientpublickey);
				EXPECT_BUFFEREQS(as->firstreceiveheaderkey, bs->firstreceiveheaderkey);
				EXPECT_BUFFEREQS(as->firstsendheaderkey, bs->firstsendheaderkey);
				EXPECT_BUFFEREQS(as->nextinitializationnonce, bs->nextinitializationnonce);
				EXPECT_BUFFEREQS(as->rootkey, bs->rootkey);
				compare_ecdh(as->localratchetstep0, bs->localratchetstep0);
				compare_ecdh(as->localratchetstep1, bs->localratchetstep1);
			}
		}
	}

	for (int i = 0; i < NUM_RATCHETS; i++)
	{
		const _mr_ratchet_state& ra = a.ratchets[i];
		const _mr_ratchet_state& rb = b.ratchets[i];
		compare_ecdh(ra.ecdhkey, rb.ecdhkey);
		EXPECT_EQ(ra.num, rb.num);
		EXPECT_EQ(ra.sendingchain.generation, rb.sendingchain.generation);
		EXPECT_EQ(ra.sendingchain.oldgeneration, rb.sendingchain.oldgeneration);
		EXPECT_BUFFEREQS(ra.nextreceiveheaderkey, rb.nextreceiveheaderkey);
		EXPECT_BUFFEREQS(ra.nextrootkey, rb.nextrootkey);
		EXPECT_BUFFEREQS(ra.nextsendheaderkey, rb.nextsendheaderkey);
		EXPECT_BUFFEREQS(ra.receiveheaderkey, rb.receiveheaderkey);
		EXPECT_BUFFEREQS(ra.receivingchain.chainkey, rb.receivingchain.chainkey);
		EXPECT_BUFFEREQS(ra.receivingchain.oldchainkey, rb.receivingchain.oldchainkey);
		EXPECT_BUFFEREQS(ra.sendheaderkey, rb.sendheaderkey);
		EXPECT_BUFFEREQS(ra.sendingchain.chainkey, rb.sendingchain.chainkey);
		EXPECT_BUFFEREQS(ra.sendingchain.oldchainkey, rb.sendingchain.oldchainkey);
	}
}

void store_and_load(_mr_ctx* ctx)
{
	uint32_t amountread;
	uint8_t storage[2048] = { 0 };
	uint32_t spaceNeeded = mr_ctx_state_size_needed(ctx);
	EXPECT_GT(spaceNeeded, (uint32_t)0);
	EXPECT_LE(spaceNeeded, sizeof(storage));
	
	mr_rng_generate(ctx->rng_ctx, storage, spaceNeeded);

	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_state_store(ctx, storage, sizeof(storage)));

	EXPECT_TRUE(is_empty_after(storage, sizeof(storage), spaceNeeded));

	_mr_ctx* ctxb = (_mr_ctx*)mr_ctx_create(&ctx->config);
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_state_load(ctxb, storage, sizeof(storage), &amountread));
	EXPECT_EQ(amountread, spaceNeeded);

	compare_states(ctx, ctxb);

	mr_ctx_destroy(ctxb);
}

void store_and_load(mr_ctx ctx) { store_and_load((_mr_ctx*)ctx); }

template<typename T>
void allocate_and_clear(mr_ctx ctx, T** ptr)
{
	ASSERT_EQ(MR_E_SUCCESS, mr_allocate(ctx, sizeof(T), (void**)ptr));
	**ptr = {};
}

#define FILLRANDOM(wut) mr_rng_generate(ctx->rng_ctx, wut, sizeof(wut))
#define CREATEECDH(wut) wut = mr_ecdh_create(ctx); mr_ecdh_generate(wut, nullptr, 0);
#define RANDOMDATA(variable, howmuch) uint8_t variable[howmuch]; mr_rng_generate(rng, variable, sizeof(variable));

void recreate_internal(mr_ctx* pctx)
{
	uint8_t* __storage = new uint8_t[2048];
	mr_config __cfg = ((_mr_ctx*)(*pctx))->config;
	mr_ecdsa_ctx __identity = ((_mr_ctx*)(*pctx))->identity;
	mr_ctx_state_store(*pctx, __storage, 2048);
	mr_ctx_destroy(*pctx);
	*pctx = nullptr;
	*pctx = mr_ctx_create(&__cfg);
	mr_ctx_state_load(*pctx, __storage, 2048, nullptr);
	mr_ctx_set_identity(*pctx, __identity, false);
	delete[] __storage;
}

#define RECREATE(ctx) recreate_internal(&ctx)

TEST(Storage, StoreLoadEmptyClient) {
	mr_config cfg{ true };
	auto ctx = mr_ctx_create(&cfg);
	store_and_load(ctx);
	mr_ctx_destroy(ctx);
}

TEST(Storage, StoreLoadEmptyServer) {
	mr_config cfg{ false };
	auto ctx = mr_ctx_create(&cfg);
	store_and_load(ctx);
	mr_ctx_destroy(ctx);
}

TEST(Storage, StoreLoadInitClient1) {
	mr_config cfg{ true };
	auto mrctx = mr_ctx_create(&cfg);
	auto ctx = (_mr_ctx*)mrctx;

	allocate_and_clear(ctx, &ctx->init.client);
	FILLRANDOM(ctx->init.client->initializationnonce);

	store_and_load(mrctx);
	mr_ctx_destroy(mrctx);
}

TEST(Storage, StoreLoadInitClient2) {
	mr_config cfg{ true };
	auto mrctx = mr_ctx_create(&cfg);
	auto ctx = (_mr_ctx*)mrctx;

	allocate_and_clear(ctx, &ctx->init.client);
	CREATEECDH(ctx->init.client->localecdhforinit);

	store_and_load(mrctx);
	mr_ctx_destroy(mrctx);
}

TEST(Storage, StoreLoadInitClient3) {
	mr_config cfg{ true };
	auto mrctx = mr_ctx_create(&cfg);
	auto ctx = (_mr_ctx*)mrctx;

	allocate_and_clear(ctx, &ctx->init.client);
	FILLRANDOM(ctx->init.client->initializationnonce);
	CREATEECDH(ctx->init.client->localecdhforinit);

	store_and_load(mrctx);
	mr_ctx_destroy(mrctx);
}

TEST(Storage, StoreLoadInitServer1) {
	mr_config cfg{ false };
	auto mrctx = mr_ctx_create(&cfg);
	auto ctx = (_mr_ctx*)mrctx;

	allocate_and_clear(ctx, &ctx->init.server);
	FILLRANDOM(ctx->init.server->clientpublickey);
	FILLRANDOM(ctx->init.server->firstreceiveheaderkey);
	FILLRANDOM(ctx->init.server->firstsendheaderkey);
	FILLRANDOM(ctx->init.server->nextinitializationnonce);
	FILLRANDOM(ctx->init.server->rootkey);
	CREATEECDH(ctx->init.server->localratchetstep0);
	CREATEECDH(ctx->init.server->localratchetstep1);

	store_and_load(mrctx);
	mr_ctx_destroy(mrctx);
}

TEST(Storage, StoreLoadInitServer2) {
	mr_config cfg{ false };
	auto mrctx = mr_ctx_create(&cfg);
	auto ctx = (_mr_ctx*)mrctx;

	allocate_and_clear(ctx, &ctx->init.server);
	FILLRANDOM(ctx->init.server->clientpublickey);
	FILLRANDOM(ctx->init.server->firstsendheaderkey);
	FILLRANDOM(ctx->init.server->rootkey);
	CREATEECDH(ctx->init.server->localratchetstep1);

	store_and_load(mrctx);
	mr_ctx_destroy(mrctx);
}

TEST(Storage, StoreLoadInitServer3) {
	mr_config cfg{ false };
	auto mrctx = mr_ctx_create(&cfg);
	auto ctx = (_mr_ctx*)mrctx;

	allocate_and_clear(ctx, &ctx->init.server);
	FILLRANDOM(ctx->init.server->firstreceiveheaderkey);
	FILLRANDOM(ctx->init.server->nextinitializationnonce);
	CREATEECDH(ctx->init.server->localratchetstep0);

	store_and_load(mrctx);
	mr_ctx_destroy(mrctx);
}

TEST(Storage, StoreLoadInitServer4) {
	mr_config cfg{ false };
	auto mrctx = mr_ctx_create(&cfg);
	auto ctx = (_mr_ctx*)mrctx;

	allocate_and_clear(ctx, &ctx->init.server);
	CREATEECDH(ctx->init.server->localratchetstep0);
	CREATEECDH(ctx->init.server->localratchetstep1);

	store_and_load(mrctx);
	mr_ctx_destroy(mrctx);
}

TEST(Storage, StoreLoadInitServer5) {
	mr_config cfg{ false };
	auto mrctx = mr_ctx_create(&cfg);
	auto ctx = (_mr_ctx*)mrctx;

	allocate_and_clear(ctx, &ctx->init.server);
	FILLRANDOM(ctx->init.server->clientpublickey);
	FILLRANDOM(ctx->init.server->firstreceiveheaderkey);
	FILLRANDOM(ctx->init.server->firstsendheaderkey);
	FILLRANDOM(ctx->init.server->nextinitializationnonce);
	FILLRANDOM(ctx->init.server->rootkey);

	store_and_load(mrctx);
	mr_ctx_destroy(mrctx);
}

TEST(Storage, Initialized) {
	mr_config cfg{ false };
	auto mrctx = mr_ctx_create(&cfg);
	auto ctx = (_mr_ctx*)mrctx;
	ctx->init.initialized = true;


	store_and_load(mrctx);
	mr_ctx_destroy(mrctx);
}

TEST(Storage, FullServer) {
	mr_config cfg{ false };
	auto mrctx = mr_ctx_create(&cfg);
	auto ctx = (_mr_ctx*)mrctx;
	ctx->init.initialized = true;

	allocate_and_clear(ctx, &ctx->init.server);
	FILLRANDOM(ctx->init.server->clientpublickey);
	FILLRANDOM(ctx->init.server->firstreceiveheaderkey);
	FILLRANDOM(ctx->init.server->firstsendheaderkey);
	FILLRANDOM(ctx->init.server->nextinitializationnonce);
	FILLRANDOM(ctx->init.server->rootkey);
	CREATEECDH(ctx->init.server->localratchetstep0);
	CREATEECDH(ctx->init.server->localratchetstep1);
	for (int i = 0; i < NUM_RATCHETS; i++)
	{
		ctx->ratchets[i].num = 1;
		CREATEECDH(ctx->ratchets[i].ecdhkey);
		FILLRANDOM(ctx->ratchets[i].nextreceiveheaderkey);
		FILLRANDOM(ctx->ratchets[i].nextrootkey);
		FILLRANDOM(ctx->ratchets[i].nextsendheaderkey);
		FILLRANDOM(ctx->ratchets[i].receiveheaderkey);
		ctx->ratchets[i].receivingchain.generation = 5;
		FILLRANDOM(ctx->ratchets[i].receivingchain.chainkey);
		ctx->ratchets[i].receivingchain.oldgeneration = 6;
		FILLRANDOM(ctx->ratchets[i].receivingchain.oldchainkey);
		FILLRANDOM(ctx->ratchets[i].sendheaderkey);
		ctx->ratchets[i].sendingchain.generation = 7;
		FILLRANDOM(ctx->ratchets[i].sendingchain.chainkey);
		ctx->ratchets[i].sendingchain.oldgeneration = 8;
		FILLRANDOM(ctx->ratchets[i].sendingchain.oldchainkey);
	}

	store_and_load(mrctx);
	mr_ctx_destroy(mrctx);
}

TEST(Storage, Ratchet1) {
	mr_config cfg{ false };
	auto mrctx = mr_ctx_create(&cfg);
	auto ctx = (_mr_ctx*)mrctx;
	ctx->init.initialized = true;

	for (int i = 0; i < NUM_RATCHETS; i++)
	{
		ctx->ratchets[i].num = i + 1;
		CREATEECDH(ctx->ratchets[i].ecdhkey);
		FILLRANDOM(ctx->ratchets[i].nextreceiveheaderkey);
		FILLRANDOM(ctx->ratchets[i].nextrootkey);
		FILLRANDOM(ctx->ratchets[i].nextsendheaderkey);
		FILLRANDOM(ctx->ratchets[i].receiveheaderkey);
		ctx->ratchets[i].receivingchain.generation = 5;
		FILLRANDOM(ctx->ratchets[i].receivingchain.chainkey);
		ctx->ratchets[i].receivingchain.oldgeneration = 6;
		FILLRANDOM(ctx->ratchets[i].receivingchain.oldchainkey);
		FILLRANDOM(ctx->ratchets[i].sendheaderkey);
		ctx->ratchets[i].sendingchain.generation = 7;
		FILLRANDOM(ctx->ratchets[i].sendingchain.chainkey);
		ctx->ratchets[i].sendingchain.oldgeneration = 8;
		FILLRANDOM(ctx->ratchets[i].sendingchain.oldchainkey);
	}

	store_and_load(mrctx);
	mr_ctx_destroy(mrctx);
}

TEST(Storage, Ratchet2) {
	mr_config cfg{ false };
	auto mrctx = mr_ctx_create(&cfg);
	auto ctx = (_mr_ctx*)mrctx;
	ctx->init.initialized = true;

	for (int i = 0; i < NUM_RATCHETS; i++)
	{
		ctx->ratchets[i].num = i + 1;
		CREATEECDH(ctx->ratchets[i].ecdhkey);
		FILLRANDOM(ctx->ratchets[i].nextreceiveheaderkey);
		FILLRANDOM(ctx->ratchets[i].nextrootkey);
		FILLRANDOM(ctx->ratchets[i].nextsendheaderkey);
		FILLRANDOM(ctx->ratchets[i].receiveheaderkey);
	}

	store_and_load(mrctx);
	mr_ctx_destroy(mrctx);
}

TEST(Storage, Ratchet3) {
	mr_config cfg{ false };
	auto mrctx = mr_ctx_create(&cfg);
	auto ctx = (_mr_ctx*)mrctx;
	ctx->init.initialized = true;

	for (int i = 0; i < NUM_RATCHETS; i++)
	{
		ctx->ratchets[i].num = i + 1;
		ctx->ratchets[i].receivingchain.generation = 5;
		FILLRANDOM(ctx->ratchets[i].receivingchain.chainkey);
		ctx->ratchets[i].receivingchain.oldgeneration = 6;
		FILLRANDOM(ctx->ratchets[i].receivingchain.oldchainkey);
		FILLRANDOM(ctx->ratchets[i].sendheaderkey);
		ctx->ratchets[i].sendingchain.generation = 7;
		FILLRANDOM(ctx->ratchets[i].sendingchain.chainkey);
		ctx->ratchets[i].sendingchain.oldgeneration = 8;
		FILLRANDOM(ctx->ratchets[i].sendingchain.oldchainkey);
	}

	store_and_load(mrctx);
	mr_ctx_destroy(mrctx);
}

TEST(Storage, Ratchet4) {
	mr_config cfg{ false };
	auto mrctx = mr_ctx_create(&cfg);
	auto ctx = (_mr_ctx*)mrctx;
	ctx->init.initialized = true;

	for (int i = 0; i < NUM_RATCHETS; i++)
	{
		ctx->ratchets[i].num = i + 1;
		CREATEECDH(ctx->ratchets[i].ecdhkey);
		FILLRANDOM(ctx->ratchets[i].nextreceiveheaderkey);
		FILLRANDOM(ctx->ratchets[i].nextsendheaderkey);
		ctx->ratchets[i].receivingchain.generation = 5;
		FILLRANDOM(ctx->ratchets[i].receivingchain.chainkey);
		FILLRANDOM(ctx->ratchets[i].sendheaderkey);
		ctx->ratchets[i].sendingchain.generation = 7;
		FILLRANDOM(ctx->ratchets[i].sendingchain.chainkey);
	}

	store_and_load(mrctx);
	mr_ctx_destroy(mrctx);
}

TEST(Storage, Ratchet5) {
	mr_config cfg{ false };
	auto mrctx = mr_ctx_create(&cfg);
	auto ctx = (_mr_ctx*)mrctx;
	ctx->init.initialized = true;

	for (int i = 0; i < NUM_RATCHETS; i++)
	{
		ctx->ratchets[i].num = i + 1;
		CREATEECDH(ctx->ratchets[i].ecdhkey);
		FILLRANDOM(ctx->ratchets[i].nextreceiveheaderkey);
		FILLRANDOM(ctx->ratchets[i].nextrootkey);
		FILLRANDOM(ctx->ratchets[i].receiveheaderkey);
		ctx->ratchets[i].receivingchain.generation = 5;
		FILLRANDOM(ctx->ratchets[i].receivingchain.chainkey);
		ctx->ratchets[i].receivingchain.oldgeneration = 6;
		FILLRANDOM(ctx->ratchets[i].receivingchain.oldchainkey);
	}

	store_and_load(mrctx);
	mr_ctx_destroy(mrctx);
}

TEST(Storage, FullProcess)
{
	constexpr size_t buffersize = 256;
	uint8_t buffer[buffersize]{};
	mr_config clientcfg{ true };
	auto client = mr_ctx_create(&clientcfg);
	mr_rng_ctx rng = mr_rng_create(client);
	uint8_t clientpubkey[32];
	auto clientidentity = mr_ecdsa_create(client);
	ASSERT_EQ(MR_E_SUCCESS, mr_ecdsa_generate(clientidentity, clientpubkey, sizeof(clientpubkey)));
	ASSERT_EQ(MR_E_SUCCESS, mr_ctx_set_identity(client, clientidentity, false));
	mr_config servercfg{ false };
	auto server = mr_ctx_create(&servercfg);
	uint8_t serverpubkey[32];
	auto serveridentity = mr_ecdsa_create(server);
	ASSERT_EQ(MR_E_SUCCESS, mr_ecdsa_generate(serveridentity, serverpubkey, sizeof(serverpubkey)));
	ASSERT_EQ(MR_E_SUCCESS, mr_ctx_set_identity(server, serveridentity, false));
	run_on_exit _a{ [=] {
		mr_rng_destroy(rng);
		mr_ctx_destroy(client);
		mr_ctx_destroy(server);
		mr_ecdsa_destroy(clientidentity);
		mr_ecdsa_destroy(serveridentity);
	} };

	ASSERT_EQ(MR_E_SENDBACK, mr_ctx_initiate_initialization(client, buffer, buffersize, false));
	RECREATE(client);
	RECREATE(server);
	ASSERT_EQ(MR_E_SENDBACK, mr_ctx_receive(server, buffer, buffersize, buffersize, nullptr, 0));
	RECREATE(client);
	RECREATE(server);
	ASSERT_EQ(MR_E_SENDBACK, mr_ctx_receive(client, buffer, buffersize, buffersize, nullptr, 0));
	RECREATE(client);
	RECREATE(server);
	ASSERT_EQ(MR_E_SENDBACK, mr_ctx_receive(server, buffer, buffersize, buffersize, nullptr, 0));
	RECREATE(client);
	RECREATE(server);
	ASSERT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buffer, buffersize, buffersize, nullptr, 0));
	RECREATE(client);
	RECREATE(server);

	RANDOMDATA(msg1, 32);
	RANDOMDATA(msg2, 32);
	RANDOMDATA(msg3, 32);
	RANDOMDATA(msg4, 32);
	RANDOMDATA(msg5, 32);
	RANDOMDATA(msg6, 32);

	uint8_t buff[128] = {};
	uint8_t* payload = 0;
	uint32_t payloadsize = 0;

	memcpy(buff, msg1, sizeof(msg1));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, sizeof(msg1), sizeof(buff)));
	RECREATE(client);
	RECREATE(server);
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	RECREATE(client);
	RECREATE(server);
	ASSERT_BUFFEREQ(msg1, sizeof(msg1), payload, sizeof(msg1));

	memcpy(buff, msg2, sizeof(msg2));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, sizeof(msg2), sizeof(buff)));
	RECREATE(client);
	RECREATE(server);
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	RECREATE(client);
	RECREATE(server);
	ASSERT_BUFFEREQ(msg2, sizeof(msg2), payload, sizeof(msg2));

	memcpy(buff, msg3, sizeof(msg3));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, sizeof(msg3), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg3, sizeof(msg3), payload, sizeof(msg3));

	memcpy(buff, msg4, sizeof(msg4));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, sizeof(msg4), sizeof(buff)));
	RECREATE(client);
	RECREATE(server);
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	RECREATE(client);
	RECREATE(server);
	ASSERT_BUFFEREQ(msg4, sizeof(msg4), payload, sizeof(msg4));

	memcpy(buff, msg5, sizeof(msg5));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, sizeof(msg5), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg5, sizeof(msg5), payload, sizeof(msg5));

	memcpy(buff, msg6, sizeof(msg6));
	RECREATE(client);
	RECREATE(server);
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, sizeof(msg6), sizeof(buff)));
	RECREATE(client);
	RECREATE(server);
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	RECREATE(client);
	RECREATE(server);
	ASSERT_BUFFEREQ(msg6, sizeof(msg6), payload, sizeof(msg6));
}