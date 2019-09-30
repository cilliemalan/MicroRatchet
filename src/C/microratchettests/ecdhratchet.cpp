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