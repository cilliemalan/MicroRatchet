#include "pch.h"
#include <microratchet.h>
#include "support.h"

static mr_config _cfg{ 1000, 1, 0, 3, 10, 1, 0 };

TEST(Ecdh, Create) {
	auto mr_ctx = mrclient_create(&_cfg);
	auto ecdh = mr_ecdh_create(mr_ctx);
	EXPECT_NE(nullptr, ecdh);

	mr_ecdh_destroy(ecdh);
	mrclient_destroy(mr_ctx);
}

TEST(Ecdh, Generate) {
	unsigned char pubkey[32];
	unsigned int pubkeysize;
	memset(pubkey, 0xCC, sizeof(pubkey));

	auto mr_ctx = mrclient_create(&_cfg);
	auto ecdh = mr_ecdh_create(mr_ctx);
	int result = call_and_wait(mr_ecdh_generate, mr_ctx, ecdh, pubkey, (unsigned int)sizeof(pubkey), &pubkeysize);
	EXPECT_EQ(E_SUCCESS, result);
	EXPECT_EQ(pubkeysize, 32);

	bool allcc = true;
	for (auto d : pubkey) if (d != 0xCC)
	{
		allcc = false; break;
	}
	EXPECT_FALSE(allcc);

	mr_ecdh_destroy(ecdh);
	mrclient_destroy(mr_ctx);
}

TEST(Ecdh, Derive) {
	auto mr_ctx = mrclient_create(&_cfg);
	auto ecdh1 = mr_ecdh_create(mr_ctx);
	auto ecdh2 = mr_ecdh_create(mr_ctx);
	EXPECT_NE(nullptr, ecdh1);
	EXPECT_NE(nullptr, ecdh2);

	unsigned char pubkey1[32];
	unsigned int pubkey1size;
	unsigned char pubkey2[32];
	unsigned int pubkey2size;
	unsigned char derived1[32];
	unsigned int derived1size;
	unsigned char derived2[32];
	unsigned int derived2size;
	int result = call_and_wait(mr_ecdh_generate, mr_ctx, ecdh1, pubkey1, (unsigned int)sizeof(pubkey1), &pubkey1size);
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_ecdh_generate, mr_ctx, ecdh2, pubkey2, (unsigned int)sizeof(pubkey2), &pubkey2size);
	EXPECT_EQ(E_SUCCESS, result);

	result = call_and_wait(mr_ecdh_derivekey, mr_ctx, ecdh1, (const unsigned char*)pubkey2, pubkey2size, derived1, (unsigned int)sizeof(derived1), &derived1size);
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_ecdh_derivekey, mr_ctx, ecdh2, (const unsigned char*)pubkey1, pubkey1size, derived2, (unsigned int)sizeof(derived2), &derived2size);
	EXPECT_EQ(E_SUCCESS, result);

	ASSERT_BUFFEREQ(derived1, derived1size, derived2, derived2size);

	mr_ecdh_destroy(ecdh1);
	mr_ecdh_destroy(ecdh2);
	mrclient_destroy(mr_ctx);
}