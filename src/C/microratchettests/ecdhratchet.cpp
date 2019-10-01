#include "pch.h"
#include <microratchet.h>
#include <internal.h>
#include "support.h"

static mr_config _cfg{ 64, 256, 1 };
static uint8_t b_empty[KEY_SIZE]{};

TEST(EcdhRatchet, ServerInitializeTest) {
	uint8_t rk[32];
	uint8_t rhk[32];
	uint8_t shk[32];
	uint8_t spub1[32];
	uint8_t spub2[32];
	uint8_t cpub[32];

	auto mr_ctx = mrclient_create(&_cfg);
	auto rng = mr_rng_create(mr_ctx);
	auto skey1 = mr_ecdh_create(mr_ctx);
	auto skey2 = mr_ecdh_create(mr_ctx);
	auto ckey = mr_ecdh_create(mr_ctx);

	mr_rng_generate(rng, rk, SIZEOF(rk));
	mr_rng_generate(rng, rhk, SIZEOF(rhk));
	mr_rng_generate(rng, shk, SIZEOF(shk));
	mr_ecdh_generate(skey1, spub1, SIZEOF(spub1));
	mr_ecdh_generate(skey2, spub2, SIZEOF(spub2));
	mr_ecdh_generate(ckey, cpub, SIZEOF(cpub));

	_mr_ratchet_state ratchet;
	
	auto result = ratchet_initialize_server(mr_ctx, &ratchet,
		skey1,
		rk, SIZEOF(rk),
		cpub, SIZEOF(cpub),
		skey2,
		rhk, SIZEOF(rhk),
		shk, SIZEOF(shk));

	EXPECT_EQ(E_SUCCESS, result);
	EXPECT_BUFFERNE(b_empty, KEY_SIZE, ratchet.nextreceiveheaderkey, KEY_SIZE);
	EXPECT_BUFFERNE(b_empty, KEY_SIZE, ratchet.nextrootkey, KEY_SIZE);
	EXPECT_BUFFERNE(b_empty, KEY_SIZE, ratchet.nextsendheaderkey, KEY_SIZE);
	EXPECT_BUFFERNE(b_empty, KEY_SIZE, ratchet.receiveheaderkey, KEY_SIZE);
	EXPECT_BUFFERNE(b_empty, KEY_SIZE, ratchet.sendheaderkey, KEY_SIZE);
	EXPECT_EQ(0, ratchet.sendingchain.generation);
	EXPECT_BUFFERNE(b_empty, KEY_SIZE, ratchet.sendingchain.chainkey, KEY_SIZE);
	EXPECT_EQ(0, ratchet.receivingchain.generation);
	EXPECT_BUFFERNE(b_empty, KEY_SIZE, ratchet.receivingchain.chainkey, KEY_SIZE);
}

TEST(EcdhRatchet, ClientInitializeTest) {
	uint8_t rk[32];
	uint8_t rhk[32];
	uint8_t shk[32];
	uint8_t spub1[32];
	uint8_t spub2[32];
	uint8_t cpub1[32];
	uint8_t cpub2[32];

	auto mr_ctx = mrclient_create(&_cfg);
	auto rng = mr_rng_create(mr_ctx);
	auto skey1 = mr_ecdh_create(mr_ctx);
	auto skey2 = mr_ecdh_create(mr_ctx);
	auto ckey1 = mr_ecdh_create(mr_ctx);
	auto ckey2 = mr_ecdh_create(mr_ctx);

	mr_rng_generate(rng, rk, SIZEOF(rk));
	mr_rng_generate(rng, rhk, SIZEOF(rhk));
	mr_rng_generate(rng, shk, SIZEOF(shk));
	mr_ecdh_generate(skey1, spub1, SIZEOF(spub1));
	mr_ecdh_generate(skey2, spub2, SIZEOF(spub2));
	mr_ecdh_generate(ckey1, cpub1, SIZEOF(cpub1));
	mr_ecdh_generate(ckey2, cpub2, SIZEOF(cpub2));

	_mr_ratchet_state ratchet1;
	_mr_ratchet_state ratchet2;

	auto result = ratchet_initialize_client(
		mr_ctx, &ratchet1, &ratchet2,
		rk, SIZEOF(rk),
		spub1, SIZEOF(spub1),
		spub2, SIZEOF(spub2),
		ckey1,
		rhk, SIZEOF(rhk),
		shk, SIZEOF(shk),
		ckey2);

	EXPECT_EQ(E_SUCCESS, result);
	EXPECT_BUFFEREQ(b_empty, KEY_SIZE, ratchet1.nextreceiveheaderkey, KEY_SIZE);
	EXPECT_BUFFEREQ(b_empty, KEY_SIZE, ratchet1.nextsendheaderkey, KEY_SIZE);
	EXPECT_BUFFEREQ(b_empty, KEY_SIZE, ratchet1.nextrootkey, KEY_SIZE);
	EXPECT_BUFFEREQ(b_empty, KEY_SIZE, ratchet1.receiveheaderkey, KEY_SIZE);
	EXPECT_BUFFERNE(b_empty, KEY_SIZE, ratchet1.sendheaderkey, KEY_SIZE);
	EXPECT_BUFFEREQ(b_empty, KEY_SIZE, ratchet1.receivingchain.chainkey, KEY_SIZE);
	EXPECT_EQ(0, ratchet1.receivingchain.generation);
	EXPECT_BUFFERNE(b_empty, KEY_SIZE, ratchet1.sendingchain.chainkey, KEY_SIZE);
	EXPECT_EQ(0, ratchet1.sendingchain.generation);

	EXPECT_BUFFERNE(b_empty, KEY_SIZE, ratchet2.nextreceiveheaderkey, KEY_SIZE);
	EXPECT_BUFFERNE(b_empty, KEY_SIZE, ratchet2.nextsendheaderkey, KEY_SIZE);
	EXPECT_BUFFERNE(b_empty, KEY_SIZE, ratchet2.nextrootkey, KEY_SIZE);
	EXPECT_BUFFERNE(b_empty, KEY_SIZE, ratchet2.receiveheaderkey, KEY_SIZE);
	EXPECT_BUFFERNE(b_empty, KEY_SIZE, ratchet2.sendheaderkey, KEY_SIZE);
	EXPECT_BUFFERNE(b_empty, KEY_SIZE, ratchet2.receivingchain.chainkey, KEY_SIZE);
	EXPECT_EQ(0, ratchet2.receivingchain.generation);
	EXPECT_BUFFERNE(b_empty, KEY_SIZE, ratchet2.sendingchain.chainkey, KEY_SIZE);
	EXPECT_EQ(0, ratchet2.sendingchain.generation);
}

TEST(EcdhRatchet, InitialChainSymmetryTest1) {
	uint8_t rk[32];
	uint8_t rhk[32];
	uint8_t shk[32];
	uint8_t spub1[32];
	uint8_t spub2[32];
	uint8_t cpub1[32];
	uint8_t cpub2[32];

	auto mr_ctx = mrclient_create(&_cfg);
	auto rng = mr_rng_create(mr_ctx);
	auto skey1 = mr_ecdh_create(mr_ctx);
	auto skey2 = mr_ecdh_create(mr_ctx);
	auto ckey1 = mr_ecdh_create(mr_ctx);
	auto ckey2 = mr_ecdh_create(mr_ctx);

	mr_rng_generate(rng, rk, SIZEOF(rk));
	mr_rng_generate(rng, rhk, SIZEOF(rhk));
	mr_rng_generate(rng, shk, SIZEOF(shk));
	mr_ecdh_generate(skey1, spub1, SIZEOF(spub1));
	mr_ecdh_generate(skey2, spub2, SIZEOF(spub2));
	mr_ecdh_generate(ckey1, cpub1, SIZEOF(cpub1));
	mr_ecdh_generate(ckey2, cpub2, SIZEOF(cpub2));

	_mr_ratchet_state sratchet;
	_mr_ratchet_state cratchet1;
	_mr_ratchet_state cratchet2;

	EXPECT_EQ(E_SUCCESS, ratchet_initialize_server(mr_ctx, &sratchet,
		skey1,
		rk, SIZEOF(rk),
		cpub1, SIZEOF(cpub1),
		skey2,
		rhk, SIZEOF(rhk),
		shk, SIZEOF(shk)));

	EXPECT_EQ(E_SUCCESS, ratchet_initialize_client(
		mr_ctx, &cratchet1, &cratchet2,
		rk, SIZEOF(rk),
		spub1, SIZEOF(spub1),
		spub2, SIZEOF(spub2),
		ckey1,
		shk, SIZEOF(shk),
		rhk, SIZEOF(rhk),
		ckey2));

	uint8_t ckey[MSG_KEY_SIZE];
	uint32_t cgen;
	uint8_t skey[MSG_KEY_SIZE];
	EXPECT_EQ(E_SUCCESS, chain_ratchetforsending(mr_ctx, &cratchet1.sendingchain, ckey, SIZEOF(ckey), &cgen));
	EXPECT_EQ(E_SUCCESS, chain_ratchetforreceiving(mr_ctx, &sratchet.receivingchain, cgen, skey, SIZEOF(skey)));

	EXPECT_BUFFEREQ(ckey, MSG_KEY_SIZE, skey, MSG_KEY_SIZE);
}

TEST(EcdhRatchet, InitialChainSymmetryTest2) {
	uint8_t rk[32];
	uint8_t rhk[32];
	uint8_t shk[32];
	uint8_t spub1[32];
	uint8_t spub2[32];
	uint8_t spub3[32];
	uint8_t cpub1[32];
	uint8_t cpub2[32];

	auto mr_ctx = mrclient_create(&_cfg);
	auto rng = mr_rng_create(mr_ctx);
	auto skey1 = mr_ecdh_create(mr_ctx);
	auto skey2 = mr_ecdh_create(mr_ctx);
	auto skey3 = mr_ecdh_create(mr_ctx);
	auto ckey1 = mr_ecdh_create(mr_ctx);
	auto ckey2 = mr_ecdh_create(mr_ctx);

	mr_rng_generate(rng, rk, SIZEOF(rk));
	mr_rng_generate(rng, rhk, SIZEOF(rhk));
	mr_rng_generate(rng, shk, SIZEOF(shk));
	mr_ecdh_generate(skey1, spub1, SIZEOF(spub1));
	mr_ecdh_generate(skey2, spub2, SIZEOF(spub2));
	mr_ecdh_generate(skey3, spub3, SIZEOF(spub3));
	mr_ecdh_generate(ckey1, cpub1, SIZEOF(cpub1));
	mr_ecdh_generate(ckey2, cpub2, SIZEOF(cpub2));

	_mr_ratchet_state sratchet1;
	_mr_ratchet_state sratchet2;
	_mr_ratchet_state cratchet1;
	_mr_ratchet_state cratchet2;

	EXPECT_EQ(E_SUCCESS, ratchet_initialize_server(mr_ctx, &sratchet1,
		skey1,
		rk, SIZEOF(rk),
		cpub1, SIZEOF(cpub1),
		skey2,
		rhk, SIZEOF(rhk),
		shk, SIZEOF(shk)));

	EXPECT_EQ(E_SUCCESS, ratchet_initialize_client(
		mr_ctx, &cratchet1, &cratchet2,
		rk, SIZEOF(rk),
		spub1, SIZEOF(spub1),
		spub2, SIZEOF(spub2),
		ckey1,
		shk, SIZEOF(shk),
		rhk, SIZEOF(rhk),
		ckey2));

	uint8_t ckey[MSG_KEY_SIZE];
	uint32_t cgen;
	uint8_t skey[MSG_KEY_SIZE];
	EXPECT_EQ(E_SUCCESS, chain_ratchetforsending(mr_ctx, &sratchet1.sendingchain, ckey, SIZEOF(ckey), &cgen));
	EXPECT_EQ(E_SUCCESS, chain_ratchetforreceiving(mr_ctx, &cratchet2.receivingchain, cgen, skey, SIZEOF(skey)));

	EXPECT_BUFFEREQ(ckey, MSG_KEY_SIZE, skey, MSG_KEY_SIZE);
}

TEST(EcdhRatchet, InitialChainRatchetTest) {
	uint8_t rk[32];
	uint8_t rhk[32];
	uint8_t shk[32];
	uint8_t spub1[32];
	uint8_t spub2[32];
	uint8_t spub3[32];
	uint8_t cpub1[32];
	uint8_t cpub2[32];

	auto mr_ctx = mrclient_create(&_cfg);
	auto rng = mr_rng_create(mr_ctx);
	auto skey1 = mr_ecdh_create(mr_ctx);
	auto skey2 = mr_ecdh_create(mr_ctx);
	auto skey3 = mr_ecdh_create(mr_ctx);
	auto ckey1 = mr_ecdh_create(mr_ctx);
	auto ckey2 = mr_ecdh_create(mr_ctx);

	mr_rng_generate(rng, rk, SIZEOF(rk));
	mr_rng_generate(rng, rhk, SIZEOF(rhk));
	mr_rng_generate(rng, shk, SIZEOF(shk));
	mr_ecdh_generate(skey1, spub1, SIZEOF(spub1));
	mr_ecdh_generate(skey2, spub2, SIZEOF(spub2));
	mr_ecdh_generate(skey3, spub3, SIZEOF(spub3));
	mr_ecdh_generate(ckey1, cpub1, SIZEOF(cpub1));
	mr_ecdh_generate(ckey2, cpub2, SIZEOF(cpub2));

	_mr_ratchet_state sratchet1;
	_mr_ratchet_state sratchet2;
	_mr_ratchet_state cratchet1;
	_mr_ratchet_state cratchet2;

	EXPECT_EQ(E_SUCCESS, ratchet_initialize_server(mr_ctx, &sratchet1,
		skey1,
		rk, SIZEOF(rk),
		cpub1, SIZEOF(cpub1),
		skey2,
		rhk, SIZEOF(rhk),
		shk, SIZEOF(shk)));

	EXPECT_EQ(E_SUCCESS, ratchet_initialize_client(
		mr_ctx, &cratchet1, &cratchet2,
		rk, SIZEOF(rk),
		spub1, SIZEOF(spub1),
		spub2, SIZEOF(spub2),
		ckey1,
		shk, SIZEOF(shk),
		rhk, SIZEOF(rhk),
		ckey2));

	EXPECT_EQ(E_SUCCESS, ratchet_ratchet(mr_ctx,
		&sratchet1,
		&sratchet2,
		cpub2, KEY_SIZE,
		skey3));

	uint8_t ckey[MSG_KEY_SIZE];
	uint32_t cgen;
	uint8_t skey[MSG_KEY_SIZE];
	EXPECT_EQ(E_SUCCESS, chain_ratchetforsending(mr_ctx, &cratchet2.sendingchain, ckey, SIZEOF(ckey), &cgen));
	EXPECT_EQ(E_SUCCESS, chain_ratchetforreceiving(mr_ctx, &sratchet2.receivingchain, cgen, skey, SIZEOF(skey)));

	EXPECT_BUFFEREQ(ckey, MSG_KEY_SIZE, skey, MSG_KEY_SIZE);
}

TEST(EcdhRatchet, SecondChainRatchetTest) {
	uint8_t rk[32];
	uint8_t rhk[32];
	uint8_t shk[32];
	uint8_t spub1[32];
	uint8_t spub2[32];
	uint8_t spub3[32];
	uint8_t cpub1[32];
	uint8_t cpub2[32];
	uint8_t cpub3[32];

	auto mr_ctx = mrclient_create(&_cfg);
	auto rng = mr_rng_create(mr_ctx);
	auto skey1 = mr_ecdh_create(mr_ctx);
	auto skey2 = mr_ecdh_create(mr_ctx);
	auto skey3 = mr_ecdh_create(mr_ctx);
	auto ckey1 = mr_ecdh_create(mr_ctx);
	auto ckey2 = mr_ecdh_create(mr_ctx);
	auto ckey3 = mr_ecdh_create(mr_ctx);

	mr_rng_generate(rng, rk, SIZEOF(rk));
	mr_rng_generate(rng, rhk, SIZEOF(rhk));
	mr_rng_generate(rng, shk, SIZEOF(shk));
	mr_ecdh_generate(skey1, spub1, SIZEOF(spub1));
	mr_ecdh_generate(skey2, spub2, SIZEOF(spub2));
	mr_ecdh_generate(skey3, spub3, SIZEOF(spub3));
	mr_ecdh_generate(ckey1, cpub1, SIZEOF(cpub1));
	mr_ecdh_generate(ckey2, cpub2, SIZEOF(cpub2));
	mr_ecdh_generate(ckey3, cpub3, SIZEOF(cpub2));

	_mr_ratchet_state sratchet1;
	_mr_ratchet_state sratchet2;
	_mr_ratchet_state cratchet1;
	_mr_ratchet_state cratchet2;
	_mr_ratchet_state cratchet3;

	EXPECT_EQ(E_SUCCESS, ratchet_initialize_server(mr_ctx, &sratchet1,
		skey1,
		rk, SIZEOF(rk),
		cpub1, SIZEOF(cpub1),
		skey2,
		rhk, SIZEOF(rhk),
		shk, SIZEOF(shk)));

	EXPECT_EQ(E_SUCCESS, ratchet_initialize_client(
		mr_ctx, &cratchet1, &cratchet2,
		rk, SIZEOF(rk),
		spub1, SIZEOF(spub1),
		spub2, SIZEOF(spub2),
		ckey1,
		shk, SIZEOF(shk),
		rhk, SIZEOF(rhk),
		ckey2));

	EXPECT_EQ(E_SUCCESS, ratchet_ratchet(mr_ctx,
		&sratchet1,
		&sratchet2,
		cpub2, KEY_SIZE,
		skey3));

	EXPECT_EQ(E_SUCCESS, ratchet_ratchet(mr_ctx,
		&cratchet2,
		&cratchet3,
		spub3, KEY_SIZE,
		ckey3));

	uint8_t ckey[MSG_KEY_SIZE];
	uint32_t cgen;
	uint8_t skey[MSG_KEY_SIZE];
	EXPECT_EQ(E_SUCCESS, chain_ratchetforsending(mr_ctx, &sratchet2.sendingchain, ckey, SIZEOF(ckey), &cgen));
	EXPECT_EQ(E_SUCCESS, chain_ratchetforreceiving(mr_ctx, &cratchet3.receivingchain, cgen, skey, SIZEOF(skey)));

	EXPECT_BUFFEREQ(ckey, MSG_KEY_SIZE, skey, MSG_KEY_SIZE);
}