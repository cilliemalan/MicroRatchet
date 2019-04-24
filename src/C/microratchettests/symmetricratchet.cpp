#include "pch.h"
#include <microratchet.h>
#include <internal.h>
#include "support.h"

#include <array>

static mr_config _cfg{ 1000, 1 };

static mr_ctx ctx;
static mr_rng_ctx rng;

template<unsigned int T>
void genrnd(unsigned char d[T]) { mr_rng_generate(rng, d, T); }
static struct __ {
	__() {
		ctx = mrclient_create(&_cfg);
		rng = mr_rng_create(ctx);
	}
} __;

TEST(SymmetricRatchet, Initialize) {
	unsigned char hk[32];
	unsigned char ck[32];
	unsigned char nhk[32];
	genrnd<32>(hk);
	genrnd<32>(ck);
	genrnd<32>(nhk);

	_mr_chain_state chain;

	auto r = chain_initialize(ctx, &chain, hk, sizeof(hk), ck, sizeof(ck), nhk, sizeof(nhk));
	ASSERT_EQ(r, E_SUCCESS);

	unsigned char zeroes[KEY_SIZE]{};
	EXPECT_EQ(0, chain.generation);
	EXPECT_BUFFEREQ(hk, sizeof(hk), chain.headerkey, sizeof(chain.headerkey));
	EXPECT_BUFFEREQ(ck, sizeof(ck), chain.chainkey, sizeof(chain.chainkey));
	EXPECT_BUFFEREQ(nhk, sizeof(nhk), chain.nextheaderkey, sizeof(chain.nextheaderkey));
	EXPECT_EQ(0, chain.oldgeneration);
	EXPECT_BUFFEREQ(zeroes, sizeof(zeroes), chain.oldchainkey, sizeof(chain.oldchainkey));
}

TEST(SymmetricRatchet, BasicSend) {
	unsigned char hk[KEY_SIZE];
	unsigned char ck[KEY_SIZE];
	unsigned char nhk[KEY_SIZE];
	genrnd<32>(hk);
	genrnd<32>(ck);
	genrnd<32>(nhk);

	_mr_chain_state chain{};

	auto r = chain_initialize(ctx, &chain, hk, sizeof(hk), ck, sizeof(ck), nhk, sizeof(nhk));
	ASSERT_EQ(r, E_SUCCESS);

	unsigned char key[MSG_KEY_SIZE]{};
	unsigned int gen;
	r = chain_ratchetforsending(ctx, &chain, key, sizeof(key), &gen);
	ASSERT_EQ(r, E_SUCCESS);

	unsigned char zeroes[MSG_KEY_SIZE]{};
	ASSERT_EQ(gen, 1);
	ASSERT_BUFFERNE(key, sizeof(key), zeroes, sizeof(zeroes));
}

TEST(SymmetricRatchet, ChainKeyModulation) {
	unsigned char hk[KEY_SIZE];
	unsigned char ck[KEY_SIZE];
	unsigned char nhk[KEY_SIZE];
	genrnd<32>(hk);
	genrnd<32>(ck);
	genrnd<32>(nhk);

	_mr_chain_state chain{};

	auto r = chain_initialize(ctx, &chain, hk, sizeof(hk), ck, sizeof(ck), nhk, sizeof(nhk));
	ASSERT_EQ(r, E_SUCCESS);

	unsigned char key[MSG_KEY_SIZE]{};
	unsigned int gen;
	r = chain_ratchetforsending(ctx, &chain, key, sizeof(key), &gen);
	ASSERT_EQ(r, E_SUCCESS);

	EXPECT_BUFFERNE(ck, sizeof(ck), chain.chainkey, sizeof(chain.chainkey));
}

TEST(SymmetricRatchet, MultiSend) {
	unsigned char hk[KEY_SIZE];
	unsigned char ck[KEY_SIZE];
	unsigned char nhk[KEY_SIZE];
	genrnd<32>(hk);
	genrnd<32>(ck);
	genrnd<32>(nhk);

	_mr_chain_state chain{};

	auto r = chain_initialize(ctx, &chain, hk, sizeof(hk), ck, sizeof(ck), nhk, sizeof(nhk));
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
}

TEST(SymmetricRatchet, BasicReceive) {
	unsigned char hk[KEY_SIZE];
	unsigned char ck[KEY_SIZE];
	unsigned char nhk[KEY_SIZE];
	genrnd<32>(hk);
	genrnd<32>(ck);
	genrnd<32>(nhk);

	_mr_chain_state chain{};

	auto r = chain_initialize(ctx, &chain, hk, sizeof(hk), ck, sizeof(ck), nhk, sizeof(nhk));
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
}

TEST(SymmetricRatchet, MultiReceive) {
	unsigned char hk[KEY_SIZE];
	unsigned char ck[KEY_SIZE];
	unsigned char nhk[KEY_SIZE];
	genrnd<32>(hk);
	genrnd<32>(ck);
	genrnd<32>(nhk);

	_mr_chain_state chain{};

	auto r = chain_initialize(ctx, &chain, hk, sizeof(hk), ck, sizeof(ck), nhk, sizeof(nhk));
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
}

TEST(SymmetricRatchet, SkipReceive) {
	unsigned char hk[KEY_SIZE];
	unsigned char ck[KEY_SIZE];
	unsigned char nhk[KEY_SIZE];
	genrnd<32>(hk);
	genrnd<32>(ck);
	genrnd<32>(nhk);

	_mr_chain_state chain{};

	auto r = chain_initialize(ctx, &chain, hk, sizeof(hk), ck, sizeof(ck), nhk, sizeof(nhk));
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
}

TEST(SymmetricRatchet, OooReceive) {
	unsigned char hk[KEY_SIZE];
	unsigned char ck[KEY_SIZE];
	unsigned char nhk[KEY_SIZE];
	genrnd<32>(hk);
	genrnd<32>(ck);
	genrnd<32>(nhk);

	_mr_chain_state chain{};

	auto r = chain_initialize(ctx, &chain, hk, sizeof(hk), ck, sizeof(ck), nhk, sizeof(nhk));
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
}

TEST(SymmetricRatchet, BasicSymmetry) {
	unsigned char hk[KEY_SIZE];
	unsigned char ck[KEY_SIZE];
	unsigned char nhk[KEY_SIZE];
	genrnd<32>(hk);
	genrnd<32>(ck);
	genrnd<32>(nhk);

	_mr_chain_state chaina{};
	_mr_chain_state chainb{};

	auto r = chain_initialize(ctx, &chaina, hk, sizeof(hk), ck, sizeof(ck), nhk, sizeof(nhk));
	ASSERT_EQ(E_SUCCESS, r);
	r = chain_initialize(ctx, &chainb, hk, sizeof(hk), ck, sizeof(ck), nhk, sizeof(nhk));
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
}

TEST(SymmetricRatchet, MultiSymmetry) {
	unsigned char hk[KEY_SIZE];
	unsigned char ck[KEY_SIZE];
	unsigned char nhk[KEY_SIZE];
	genrnd<32>(hk);
	genrnd<32>(ck);
	genrnd<32>(nhk);

	_mr_chain_state chaina{};
	_mr_chain_state chainb{};

	auto r = chain_initialize(ctx, &chaina, hk, sizeof(hk), ck, sizeof(ck), nhk, sizeof(nhk));
	ASSERT_EQ(E_SUCCESS, r);
	r = chain_initialize(ctx, &chainb, hk, sizeof(hk), ck, sizeof(ck), nhk, sizeof(nhk));
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
}

void deepsymmetrytest(int depth)
{
	unsigned char hk[KEY_SIZE];
	unsigned char ck[KEY_SIZE];
	unsigned char nhk[KEY_SIZE];
	genrnd<32>(hk);
	genrnd<32>(ck);
	genrnd<32>(nhk);

	_mr_chain_state chaina{};
	_mr_chain_state chainb{};

	auto r = chain_initialize(ctx, &chaina, hk, sizeof(hk), ck, sizeof(ck), nhk, sizeof(nhk));
	ASSERT_EQ(E_SUCCESS, r);
	r = chain_initialize(ctx, &chainb, hk, sizeof(hk), ck, sizeof(ck), nhk, sizeof(nhk));
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
}

TEST(SymmetricRatchet, DeepSymmetry10) { deepsymmetrytest(10); }
TEST(SymmetricRatchet, DeepSymmetry100) { deepsymmetrytest(100); }
TEST(SymmetricRatchet, DeepSymmetry1000) { deepsymmetrytest(1000); }
TEST(SymmetricRatchet, DeepSymmetry10000) { deepsymmetrytest(10000); }

void receivetest(int depth)
{
	unsigned char hk[KEY_SIZE];
	unsigned char ck[KEY_SIZE];
	unsigned char nhk[KEY_SIZE];
	genrnd<32>(hk);
	genrnd<32>(ck);
	genrnd<32>(nhk);

	_mr_chain_state chain{};

	auto r = chain_initialize(ctx, &chain, hk, sizeof(hk), ck, sizeof(ck), nhk, sizeof(nhk));
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
}

TEST(SymmetricRatchet, RatchetForReceivingMany10) { receivetest(10); }
TEST(SymmetricRatchet, RatchetForReceivingMany100) { receivetest(100); }
TEST(SymmetricRatchet, RatchetForReceivingMany1000) { receivetest(1000); }
TEST(SymmetricRatchet, RatchetForReceivingMany10000) { receivetest(10000); }

TEST(SymmetricRatchet, Reference) {
}
