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

void store_and_load(_mr_ctx *ctx)
{
	uint32_t amountread;
	uint8_t storage[2048] = { 0 };
	uint32_t spaceNeeded = mr_ctx_state_size_needed(ctx);
	EXPECT_GT(spaceNeeded, (uint32_t)0);

	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_state_store(ctx, storage, sizeof(storage)));

	EXPECT_TRUE(is_empty_after(storage, sizeof(storage), spaceNeeded));

	_mr_ctx* ctxb = (_mr_ctx*)mr_ctx_create(&ctx->config);
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_state_load(ctxb, storage, sizeof(storage), &amountread));

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
	ctx->init.client->initializationnonce[0] = 1;
	ctx->init.client->initializationnonce[15] = 2;

	store_and_load(mrctx);
	mr_ctx_destroy(mrctx);
}

TEST(Storage, StoreLoadInitClient2) {
	mr_config cfg{ true };
	auto mrctx = mr_ctx_create(&cfg);
	auto ctx = (_mr_ctx*)mrctx;

	allocate_and_clear(ctx, &ctx->init.client);
	ctx->init.client->localecdhforinit = mr_ecdh_create(ctx);
	mr_ecdh_generate(ctx->init.client->localecdhforinit, nullptr, 0);

	store_and_load(mrctx);
	mr_ctx_destroy(mrctx);
}

TEST(Storage, StoreLoadInitClient3) {
	mr_config cfg{ true };
	auto mrctx = mr_ctx_create(&cfg);
	auto ctx = (_mr_ctx*)mrctx;

	allocate_and_clear(ctx, &ctx->init.client);
	ctx->init.client->initializationnonce[0] = 1;
	ctx->init.client->initializationnonce[15] = 2;
	ctx->init.client->localecdhforinit = mr_ecdh_create(ctx);
	mr_ecdh_generate(ctx->init.client->localecdhforinit, nullptr, 0);

	store_and_load(mrctx);
	mr_ctx_destroy(mrctx);
}