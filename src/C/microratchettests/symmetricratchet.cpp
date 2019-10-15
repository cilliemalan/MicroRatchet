#include "pch.h"
#include <microratchet.h>
#include <internal.h>
#include "support.h"

#include <array>

static mr_config _cfg{ true };

TEST(SymmetricRatchet, Initialize) {
	mr_ctx ctx = mr_ctx_create(&_cfg);
	mr_rng_ctx rng = mr_rng_create(ctx);

	unsigned char ck[32];
	mr_rng_generate(rng, ck, sizeof(ck));

	_mr_chain_state chain;

	auto r = chain_initialize(ctx, &chain, ck, sizeof(ck));
	ASSERT_EQ(r, E_SUCCESS);

	unsigned char zeroes[KEY_SIZE]{};
	EXPECT_EQ(0, chain.generation);
	EXPECT_BUFFEREQ(ck, sizeof(ck), chain.chainkey, sizeof(chain.chainkey));
	EXPECT_EQ(0, chain.oldgeneration);
	EXPECT_BUFFEREQ(zeroes, sizeof(zeroes), chain.oldchainkey, sizeof(chain.oldchainkey));

	mr_rng_destroy(rng);
	mr_ctx_destroy(ctx);
}

TEST(SymmetricRatchet, BasicSend) {
	mr_ctx ctx = mr_ctx_create(&_cfg);
	mr_rng_ctx rng = mr_rng_create(ctx);

	unsigned char ck[KEY_SIZE];
	mr_rng_generate(rng, ck, sizeof(ck));

	_mr_chain_state chain{};

	auto r = chain_initialize(ctx, &chain, ck, sizeof(ck));
	ASSERT_EQ(r, E_SUCCESS);

	unsigned char key[MSG_KEY_SIZE]{};
	unsigned int gen;
	r = chain_ratchetforsending(ctx, &chain, key, sizeof(key), &gen);
	ASSERT_EQ(r, E_SUCCESS);

	unsigned char zeroes[MSG_KEY_SIZE]{};
	ASSERT_EQ(gen, 1);
	ASSERT_BUFFERNE(key, sizeof(key), zeroes, sizeof(zeroes));

	mr_rng_destroy(rng);
	mr_ctx_destroy(ctx);
}

TEST(SymmetricRatchet, ChainKeyModulation) {
	mr_ctx ctx = mr_ctx_create(&_cfg);
	mr_rng_ctx rng = mr_rng_create(ctx);

	unsigned char ck[32];
	mr_rng_generate(rng, ck, sizeof(ck));

	_mr_chain_state chain{};

	auto r = chain_initialize(ctx, &chain, ck, sizeof(ck));
	ASSERT_EQ(r, E_SUCCESS);

	unsigned char key[MSG_KEY_SIZE]{};
	unsigned int gen;
	r = chain_ratchetforsending(ctx, &chain, key, sizeof(key), &gen);
	ASSERT_EQ(r, E_SUCCESS);

	EXPECT_BUFFERNE(ck, sizeof(ck), chain.chainkey, sizeof(chain.chainkey));

	mr_rng_destroy(rng);
	mr_ctx_destroy(ctx);
}

TEST(SymmetricRatchet, MultiSend) {
	mr_ctx ctx = mr_ctx_create(&_cfg);
	mr_rng_ctx rng = mr_rng_create(ctx);

	unsigned char ck[32];
	mr_rng_generate(rng, ck, sizeof(ck));

	_mr_chain_state chain{};

	auto r = chain_initialize(ctx, &chain, ck, sizeof(ck));
	ASSERT_EQ(r, E_SUCCESS);

	unsigned char key1[MSG_KEY_SIZE]{};
	unsigned char key2[MSG_KEY_SIZE]{};
	unsigned int gen1;
	unsigned int gen2;
	r = chain_ratchetforsending(ctx, &chain, key1, sizeof(key1), &gen1);
	ASSERT_EQ(E_SUCCESS, r);
	r = chain_ratchetforsending(ctx, &chain, key2, sizeof(key2), &gen2);
	ASSERT_EQ(r, E_SUCCESS);

	unsigned char zeroes[MSG_KEY_SIZE]{};
	ASSERT_EQ(gen1, 1);
	ASSERT_BUFFERNE(key1, sizeof(key1), zeroes, sizeof(zeroes));
	ASSERT_EQ(gen2, 2);
	ASSERT_BUFFERNE(key2, sizeof(key2), zeroes, sizeof(zeroes));
	ASSERT_BUFFERNE(key1, sizeof(key1), key2, sizeof(key2));

	mr_rng_destroy(rng);
	mr_ctx_destroy(ctx);
}

TEST(SymmetricRatchet, BasicReceive) {
	mr_ctx ctx = mr_ctx_create(&_cfg);
	mr_rng_ctx rng = mr_rng_create(ctx);

	unsigned char ck[32];
	mr_rng_generate(rng, ck, sizeof(ck));

	_mr_chain_state chain{};

	auto r = chain_initialize(ctx, &chain, ck, sizeof(ck));
	ASSERT_EQ(r, E_SUCCESS);

	unsigned char key[MSG_KEY_SIZE]{};
	r = chain_ratchetforreceiving(ctx, &chain, 1, key, sizeof(key));
	ASSERT_EQ(E_SUCCESS, r);

	unsigned char zeroes[MSG_KEY_SIZE]{};
	unsigned char zeroes32[KEY_SIZE]{};
	ASSERT_BUFFERNE(key, sizeof(key), zeroes, sizeof(zeroes));

	EXPECT_BUFFERNE(ck, sizeof(ck), chain.chainkey, sizeof(chain.chainkey));
	EXPECT_EQ(1, chain.generation);
	EXPECT_EQ(0, chain.oldgeneration);
	ASSERT_BUFFEREQ(zeroes32, sizeof(zeroes32), chain.oldchainkey, sizeof(chain.oldchainkey));

	mr_rng_destroy(rng);
	mr_ctx_destroy(ctx);
}

TEST(SymmetricRatchet, MultiReceive) {
	mr_ctx ctx = mr_ctx_create(&_cfg);
	mr_rng_ctx rng = mr_rng_create(ctx);

	unsigned char ck[32];
	mr_rng_generate(rng, ck, sizeof(ck));

	_mr_chain_state chain{};

	auto r = chain_initialize(ctx, &chain, ck, sizeof(ck));
	ASSERT_EQ(r, E_SUCCESS);

	unsigned char key1[MSG_KEY_SIZE]{};
	unsigned char key2[MSG_KEY_SIZE]{};
	r = chain_ratchetforreceiving(ctx, &chain, 1, key1, sizeof(key1));
	ASSERT_EQ(E_SUCCESS, r);
	r = chain_ratchetforreceiving(ctx, &chain, 2, key2, sizeof(key2));
	ASSERT_EQ(E_SUCCESS, r);

	unsigned char zeroes[MSG_KEY_SIZE]{};
	unsigned char zeroes32[KEY_SIZE]{};
	ASSERT_BUFFERNE(key1, sizeof(key1), zeroes, sizeof(zeroes));
	ASSERT_BUFFERNE(key2, sizeof(key2), zeroes, sizeof(zeroes));
	ASSERT_BUFFERNE(key2, sizeof(key2), key1, sizeof(key1));

	EXPECT_BUFFERNE(ck, sizeof(ck), chain.chainkey, sizeof(chain.chainkey));
	EXPECT_EQ(2, chain.generation);
	EXPECT_EQ(0, chain.oldgeneration);
	EXPECT_BUFFEREQ(zeroes32, sizeof(zeroes32), chain.oldchainkey, sizeof(chain.oldchainkey));

	mr_rng_destroy(rng);
	mr_ctx_destroy(ctx);
}

TEST(SymmetricRatchet, SkipReceive) {
	mr_ctx ctx = mr_ctx_create(&_cfg);
	mr_rng_ctx rng = mr_rng_create(ctx);

	unsigned char ck[32];
	mr_rng_generate(rng, ck, sizeof(ck));

	_mr_chain_state chain{};

	auto r = chain_initialize(ctx, &chain, ck, sizeof(ck));
	ASSERT_EQ(r, E_SUCCESS);

	unsigned char key1[MSG_KEY_SIZE]{};
	unsigned char key2[MSG_KEY_SIZE]{};
	r = chain_ratchetforreceiving(ctx, &chain, 1, key1, sizeof(key1));
	ASSERT_EQ(E_SUCCESS, r);
	r = chain_ratchetforreceiving(ctx, &chain, 10, key2, sizeof(key2));
	ASSERT_EQ(E_SUCCESS, r);

	unsigned char zeroes[MSG_KEY_SIZE]{};
	EXPECT_BUFFERNE(key1, sizeof(key1), zeroes, sizeof(zeroes));
	EXPECT_BUFFERNE(key2, sizeof(key2), zeroes, sizeof(zeroes));
	EXPECT_BUFFERNE(key2, sizeof(key2), key1, sizeof(key1));

	EXPECT_EQ(chain.generation, 10);
	EXPECT_EQ(chain.oldgeneration, 1);

	mr_rng_destroy(rng);
	mr_ctx_destroy(ctx);
}

TEST(SymmetricRatchet, OooReceive) {
	mr_ctx ctx = mr_ctx_create(&_cfg);
	mr_rng_ctx rng = mr_rng_create(ctx);

	unsigned char ck[32];
	mr_rng_generate(rng, ck, sizeof(ck));

	_mr_chain_state chain{};

	auto r = chain_initialize(ctx, &chain, ck, sizeof(ck));
	ASSERT_EQ(r, E_SUCCESS);

	unsigned char key1[MSG_KEY_SIZE]{};
	unsigned char key2[MSG_KEY_SIZE]{};
	unsigned char key3[MSG_KEY_SIZE]{};
	unsigned char key4[MSG_KEY_SIZE]{};
	r = chain_ratchetforreceiving(ctx, &chain, 1, key1, sizeof(key1));
	ASSERT_EQ(E_SUCCESS, r);
	r = chain_ratchetforreceiving(ctx, &chain, 10, key2, sizeof(key2));
	ASSERT_EQ(E_SUCCESS, r);
	r = chain_ratchetforreceiving(ctx, &chain, 5, key3, sizeof(key3));
	ASSERT_EQ(E_SUCCESS, r);
	r = chain_ratchetforreceiving(ctx, &chain, 2, key4, sizeof(key4));
	ASSERT_EQ(E_SUCCESS, r);

	unsigned char zeroes[MSG_KEY_SIZE]{};
	EXPECT_BUFFERNE(key1, sizeof(key1), zeroes, sizeof(zeroes));
	EXPECT_BUFFERNE(key2, sizeof(key2), zeroes, sizeof(zeroes));
	EXPECT_BUFFERNE(key3, sizeof(key2), zeroes, sizeof(zeroes));
	EXPECT_BUFFERNE(key4, sizeof(key2), zeroes, sizeof(zeroes));

	EXPECT_EQ(chain.generation, 10);
	EXPECT_EQ(chain.oldgeneration, 2);

	mr_rng_destroy(rng);
	mr_ctx_destroy(ctx);
}

TEST(SymmetricRatchet, BasicSymmetry) {
	mr_ctx ctx = mr_ctx_create(&_cfg);
	mr_rng_ctx rng = mr_rng_create(ctx);

	unsigned char ck[32];
	mr_rng_generate(rng, ck, sizeof(ck));

	_mr_chain_state chaina{};
	_mr_chain_state chainb{};
	
	auto r = chain_initialize(ctx, &chaina, ck, sizeof(ck));
	ASSERT_EQ(E_SUCCESS, r);
	r = chain_initialize(ctx, &chainb, ck, sizeof(ck));
	ASSERT_EQ(E_SUCCESS, r);

	unsigned char keya[MSG_KEY_SIZE]{};
	unsigned int gen;
	unsigned char keyb[MSG_KEY_SIZE]{};
	unsigned char zeroes[MSG_KEY_SIZE]{};
	r = chain_ratchetforsending(ctx, &chaina, keya, sizeof(keya), &gen);
	ASSERT_EQ(E_SUCCESS, r);
	r = chain_ratchetforreceiving(ctx, &chainb, gen, keyb, sizeof(keyb));
	ASSERT_EQ(E_SUCCESS, r);

	EXPECT_BUFFEREQ(keya, sizeof(keya), keyb, sizeof(keyb));
	EXPECT_BUFFERNE(zeroes, sizeof(zeroes), keyb, sizeof(keyb));

	mr_rng_destroy(rng);
	mr_ctx_destroy(ctx);
}

TEST(SymmetricRatchet, MultiSymmetry) {
	mr_ctx ctx = mr_ctx_create(&_cfg);
	mr_rng_ctx rng = mr_rng_create(ctx);

	unsigned char ck[32];
	mr_rng_generate(rng, ck, sizeof(ck));

	_mr_chain_state chaina{};
	_mr_chain_state chainb{};

	auto r = chain_initialize(ctx, &chaina, ck, sizeof(ck));
	ASSERT_EQ(E_SUCCESS, r);
	r = chain_initialize(ctx, &chainb, ck, sizeof(ck));
	ASSERT_EQ(E_SUCCESS, r);

	unsigned int gen1;
	unsigned char keya1[MSG_KEY_SIZE]{};
	unsigned char keyb1[MSG_KEY_SIZE]{};
	unsigned int gen2;
	unsigned char keya2[MSG_KEY_SIZE]{};
	unsigned char keyb2[MSG_KEY_SIZE]{};
	unsigned char zeroes[MSG_KEY_SIZE]{};
	r = chain_ratchetforsending(ctx, &chaina, keya1, sizeof(keya1), &gen1);
	ASSERT_EQ(E_SUCCESS, r);
	r = chain_ratchetforsending(ctx, &chaina, keya2, sizeof(keya2), &gen2);
	ASSERT_EQ(E_SUCCESS, r);
	r = chain_ratchetforreceiving(ctx, &chainb, gen1, keyb1, sizeof(keyb1));
	ASSERT_EQ(E_SUCCESS, r);
	r = chain_ratchetforreceiving(ctx, &chainb, gen2, keyb2, sizeof(keyb2));
	ASSERT_EQ(E_SUCCESS, r);

	EXPECT_BUFFEREQ(keya1, sizeof(keya1), keyb1, sizeof(keyb1));
	EXPECT_BUFFEREQ(keya2, sizeof(keya2), keyb2, sizeof(keyb2));
	EXPECT_BUFFERNE(zeroes, sizeof(zeroes), keyb1, sizeof(keyb1));
	EXPECT_BUFFERNE(zeroes, sizeof(zeroes), keyb2, sizeof(keyb2));
	EXPECT_BUFFERNE(keya1, sizeof(keya1), keyb2, sizeof(keyb2));
	EXPECT_NE(gen1, gen2);

	mr_rng_destroy(rng);
	mr_ctx_destroy(ctx);
}

void deepsymmetrytest(int depth) 
{
	mr_ctx ctx = mr_ctx_create(&_cfg);
	mr_rng_ctx rng = mr_rng_create(ctx);

	unsigned char ck[32];
	mr_rng_generate(rng, ck, sizeof(ck));

	_mr_chain_state chaina{};
	_mr_chain_state chainb{};

	auto r = chain_initialize(ctx, &chaina, ck, sizeof(ck));
	ASSERT_EQ(E_SUCCESS, r);
	r = chain_initialize(ctx, &chainb, ck, sizeof(ck));
	ASSERT_EQ(E_SUCCESS, r);

	unsigned int gen = 0;
	unsigned char keya[MSG_KEY_SIZE]{};
	unsigned char keyb[MSG_KEY_SIZE]{};
	while (gen != depth)
	{
		r = chain_ratchetforsending(ctx, &chaina, keya, sizeof(keya), &gen);
		ASSERT_EQ(E_SUCCESS, r);
	}

	r = chain_ratchetforreceiving(ctx, &chainb, gen, keyb, sizeof(keyb));
	ASSERT_EQ(E_SUCCESS, r);

	unsigned char zeroes[MSG_KEY_SIZE]{};
	EXPECT_BUFFEREQ(keya, sizeof(keya), keyb, sizeof(keyb));
	EXPECT_BUFFERNE(zeroes, sizeof(zeroes), keyb, sizeof(keyb));

	mr_rng_destroy(rng);
	mr_ctx_destroy(ctx);
}

TEST(SymmetricRatchet, DeepSymmetry10) { deepsymmetrytest(10); }
TEST(SymmetricRatchet, DeepSymmetry100) { deepsymmetrytest(100); }
TEST(SymmetricRatchet, DeepSymmetry1000) { deepsymmetrytest(1000); }
TEST(SymmetricRatchet, DeepSymmetry10000) { deepsymmetrytest(10000); }

void receivetest(int depth)
{
	mr_ctx ctx = mr_ctx_create(&_cfg);
	mr_rng_ctx rng = mr_rng_create(ctx);

	unsigned char ck[32];
	mr_rng_generate(rng, ck, sizeof(ck));

	_mr_chain_state chain{};

	auto r = chain_initialize(ctx, &chain, ck, sizeof(ck));
	ASSERT_EQ(r, E_SUCCESS);

	unsigned char key[MSG_KEY_SIZE]{};
	r = chain_ratchetforreceiving(ctx, &chain, depth, key, sizeof(key));
	ASSERT_EQ(E_SUCCESS, r);

	unsigned char zeroes[MSG_KEY_SIZE]{};
	unsigned char zeroes32[KEY_SIZE]{};
	ASSERT_BUFFERNE(key, sizeof(key), zeroes, sizeof(zeroes));

	EXPECT_BUFFERNE(ck, sizeof(ck), chain.chainkey, sizeof(chain.chainkey));
	EXPECT_EQ(depth, chain.generation);
	EXPECT_EQ(0, chain.oldgeneration);
	ASSERT_BUFFERNE(zeroes32, sizeof(zeroes32), chain.oldchainkey, sizeof(chain.oldchainkey));

	mr_rng_destroy(rng);
	mr_ctx_destroy(ctx);
}

TEST(SymmetricRatchet, RatchetForReceivingMany10) { receivetest(10); }
TEST(SymmetricRatchet, RatchetForReceivingMany100) { receivetest(100); }
TEST(SymmetricRatchet, RatchetForReceivingMany1000) { receivetest(1000); }
TEST(SymmetricRatchet, RatchetForReceivingMany10000) { receivetest(10000); }

void testratchet(const unsigned char chainkey[], size_t chainkeysize,
	unsigned int generation,
	const unsigned char expectedkey[], size_t expectedkeysize)
{
	auto ctx = mr_ctx_create(&_cfg);
	_mr_chain_state chain{};
	
	auto r = chain_initialize(ctx, &chain, chainkey, (uint32_t)chainkeysize);
	ASSERT_EQ(r, E_SUCCESS);

	unsigned char key[MSG_KEY_SIZE]{};
	r = chain_ratchetforreceiving(ctx, &chain, generation, key, sizeof(key));
	ASSERT_EQ(E_SUCCESS, r);
	ASSERT_BUFFEREQ(key, sizeof(key), expectedkey, (unsigned int)expectedkeysize);

	mr_ctx_destroy(ctx);
}

TEST(SymmetricRatchet, Reference1) {
	const unsigned char chain[]{
		0x77, 0xca, 0x3d, 0xca, 0x28, 0x86, 0xe9, 0xe4,
		0x93, 0xf2, 0xe7, 0x8a, 0xfe, 0x62, 0x81, 0x69,
		0x92, 0x29, 0x93, 0x0e, 0x7a, 0x5e, 0x9e, 0x34,
		0x3f, 0x5a, 0xb3, 0x12, 0xc3, 0xae, 0x3c, 0x32
	};
	unsigned int gen = 39479;
	const unsigned char key[]{
		0x00, 0x75, 0xd8, 0xad, 0xe6, 0xcb, 0xbf, 0xa0,
		0x79, 0xb5, 0xe0, 0xeb, 0x36, 0x96, 0x35, 0x2c
	};
	testratchet(chain, sizeof(chain), gen, key, sizeof(key));
}

TEST(SymmetricRatchet, Reference2) {
	const unsigned char chain[]{
		0x7c, 0x0c, 0x8a, 0x0f, 0x87, 0x7b, 0x4b, 0x31,
		0x09, 0xfd, 0xc5, 0xbf, 0x31, 0x80, 0xaa, 0xfa,
		0x28, 0x9d, 0xe2, 0x08, 0x0a, 0x44, 0xe5, 0x95,
		0x32, 0x31, 0x92, 0x29, 0x7e, 0x7a, 0x7f, 0xad
	};
	unsigned int gen = 94435;
	const unsigned char key[]{
		0x29, 0x31, 0xc7, 0xe3,0xbf, 0xab, 0xcd, 0x5c,
		0x85, 0x44, 0x1d, 0xf4, 0x77, 0x8f, 0x09, 0x3d
	};
	testratchet(chain, sizeof(chain), gen, key, sizeof(key));
}

TEST(SymmetricRatchet, Reference3) {
	const unsigned char chain[]{
		0x57, 0x2d, 0x42, 0x30, 0x60, 0xd8, 0xca, 0xa7,
		0xca, 0xd0, 0x89, 0x0e, 0x0a, 0x33, 0x47, 0x2a,
		0xef, 0x71, 0x75, 0xa3, 0x29, 0x22, 0xf5, 0x6e,
		0x97, 0x46, 0xcd, 0xf3, 0xdf, 0x51, 0x5f, 0x37
	};
	unsigned int gen = 11164;
	const unsigned char key[]{
		0x33, 0xc9, 0x48, 0xb7, 0x1f, 0xdc, 0x17, 0xb0,
		0x0e, 0xef, 0x7a, 0x2a, 0x89, 0x20, 0x37, 0x09
	};
	testratchet(chain, sizeof(chain), gen, key, sizeof(key));
}

TEST(SymmetricRatchet, Reference4) {
	const unsigned char chain[]{
		0xa6, 0xb9, 0x29, 0x93, 0x1d, 0x68, 0x74, 0xcf,
		0x66, 0x3e, 0x2c, 0xef, 0xf5, 0x8a, 0x73, 0x8c,
		0xa6, 0x7b, 0x24, 0x34, 0xbc, 0xb0, 0x0e, 0x0c,
		0x48, 0x5d, 0xe5, 0xf5, 0xeb, 0x03, 0xa0, 0x1e
	};
	unsigned int gen = 58129;
	const unsigned char key[]{
		0xaf, 0x82, 0x60, 0x58, 0x7f, 0x78, 0xb3, 0x96,
		0xd2, 0xea, 0x65, 0x5b, 0xec, 0xa5, 0x9a, 0x36
	};
	testratchet(chain, sizeof(chain), gen, key, sizeof(key));
}

TEST(SymmetricRatchet, Reference5) {
	const unsigned char chain[]{
		0xf9, 0xad, 0xcc, 0x2b, 0x22, 0x3f, 0x82, 0x16,
		0xa4, 0x8b, 0xec, 0xb9, 0xa2, 0x3e, 0x9b, 0xe1,
		0x24, 0x61, 0x07, 0xbe, 0x9c, 0x7b, 0xbd, 0x73,
		0xa4, 0x1e, 0xa6, 0xe8, 0x45, 0xe5, 0xee, 0x51
	};
	unsigned int gen = 97922;
	const unsigned char key[]{
		0xd4, 0x23, 0xb7, 0x51, 0xb4, 0x77, 0xcf, 0xef,
		0xe4, 0x4e, 0x55, 0xe6, 0x6e, 0x52, 0x31, 0x63
	};
	testratchet(chain, sizeof(chain), gen, key, sizeof(key));
}
