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
	int result = call_and_wait(mr_ecdh_generate, mr_ctx, ecdh1, pubkey1, (unsigned int)sizeof(pubkey1), &pubkey1size);
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_ecdh_generate, mr_ctx, ecdh2, pubkey2, (unsigned int)sizeof(pubkey2), &pubkey2size);
	EXPECT_EQ(E_SUCCESS, result);

	unsigned char derived1[32];
	unsigned int derived1size;
	unsigned char derived2[32];
	unsigned int derived2size;
	result = call_and_wait(mr_ecdh_derivekey, mr_ctx, ecdh1, (const unsigned char*)pubkey2, pubkey2size, derived1, (unsigned int)sizeof(derived1), &derived1size);
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_ecdh_derivekey, mr_ctx, ecdh2, (const unsigned char*)pubkey1, pubkey1size, derived2, (unsigned int)sizeof(derived2), &derived2size);
	EXPECT_EQ(E_SUCCESS, result);

	EXPECT_BUFFEREQ(derived1, derived1size, derived2, derived2size);

	mr_ecdh_destroy(ecdh1);
	mr_ecdh_destroy(ecdh2);
	mrclient_destroy(mr_ctx);
}

TEST(Ecdh, StoreLoadDeriveTest) {
	auto mr_ctx = mrclient_create(&_cfg);
	auto ecdh1 = mr_ecdh_create(mr_ctx);
	auto ecdh2 = mr_ecdh_create(mr_ctx);
	auto ecdh3 = mr_ecdh_create(mr_ctx);
	auto ecdh4 = mr_ecdh_create(mr_ctx);
	EXPECT_NE(nullptr, ecdh1);
	EXPECT_NE(nullptr, ecdh2);

	// use the first two ecdhes, generate the other two
	unsigned char pubkey1[32];
	unsigned int pubkey1size;
	unsigned char pubkey2[32];
	unsigned int pubkey2size;
	unsigned char pubkey3[32];
	unsigned int pubkey3size;
	unsigned char pubkey4[32];
	unsigned int pubkey4size;
	int result = call_and_wait(mr_ecdh_generate, mr_ctx, ecdh1, pubkey1, (unsigned int)sizeof(pubkey1), &pubkey1size);
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_ecdh_generate, mr_ctx, ecdh2, pubkey2, (unsigned int)sizeof(pubkey2), &pubkey2size);
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_ecdh_generate, mr_ctx, ecdh3, pubkey3, (unsigned int)sizeof(pubkey3), &pubkey3size);
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_ecdh_generate, mr_ctx, ecdh4, pubkey4, (unsigned int)sizeof(pubkey4), &pubkey4size);
	EXPECT_EQ(E_SUCCESS, result);

	// derive a key with the first two
	unsigned char derived1[32];
	unsigned int derived1size;
	unsigned char derived2[32];
	unsigned int derived2size;
	result = call_and_wait(mr_ecdh_derivekey, mr_ctx, ecdh1, (const unsigned char*)pubkey2, pubkey2size, derived1, (unsigned int)sizeof(derived1), &derived1size);
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_ecdh_derivekey, mr_ctx, ecdh2, (const unsigned char*)pubkey1, pubkey1size, derived2, (unsigned int)sizeof(derived2), &derived2size);
	EXPECT_EQ(E_SUCCESS, result);
	EXPECT_BUFFEREQ(derived1, derived1size, derived2, derived2size);

	// derive a key with the other two
	unsigned char derived3[32];
	unsigned int derived3size;
	unsigned char derived4[32];
	unsigned int derived4size;
	result = call_and_wait(mr_ecdh_derivekey, mr_ctx, ecdh3, (const unsigned char*)pubkey4, pubkey4size, derived3, (unsigned int)sizeof(derived3), &derived3size);
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_ecdh_derivekey, mr_ctx, ecdh4, (const unsigned char*)pubkey3, pubkey3size, derived4, (unsigned int)sizeof(derived4), &derived4size);
	EXPECT_EQ(E_SUCCESS, result);
	EXPECT_BUFFEREQ(derived3, derived3size, derived4, derived4size);

	// 1&2 and 3&4 must not be the same
	EXPECT_BUFFERNE(derived1, derived1size, derived3, derived3size);

	// store the first two ecdhes
	unsigned char storage1[64];
	unsigned int storage1used;
	unsigned char storage2[64];
	unsigned int storage2used;

	result = call_and_wait(mr_ecdh_store, mr_ctx, ecdh1, storage1, (unsigned int)sizeof(storage1), &storage1used);
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_ecdh_store, mr_ctx, ecdh2, storage2, (unsigned int)sizeof(storage2), &storage2used);
	EXPECT_EQ(E_SUCCESS, result);

	// destroy the first two ecdhes
	mr_ecdh_destroy(ecdh1);
	mr_ecdh_destroy(ecdh2);

	// load the stored params into 3&4
	result = call_and_wait(mr_ecdh_load, mr_ctx, ecdh3, storage1, storage1used);
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_ecdh_load, mr_ctx, ecdh4, storage2, storage2used);
	EXPECT_EQ(E_SUCCESS, result);

	// now generate keys again
	unsigned char derived5[32];
	unsigned int derived5size;
	unsigned char derived6[32];
	unsigned int derived6size;
	result = call_and_wait(mr_ecdh_derivekey, mr_ctx, ecdh3, (const unsigned char*)pubkey2, pubkey2size, derived5, (unsigned int)sizeof(derived5), &derived5size);
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_ecdh_derivekey, mr_ctx, ecdh4, (const unsigned char*)pubkey1, pubkey1size, derived6, (unsigned int)sizeof(derived6), &derived6size);
	EXPECT_EQ(E_SUCCESS, result);

	// and check them
	EXPECT_BUFFEREQ(derived1, derived1size, derived5, derived5size);
	EXPECT_BUFFEREQ(derived2, derived2size, derived6, derived6size);
	EXPECT_BUFFERNE(derived3, derived3size, derived6, derived6size);
	EXPECT_BUFFERNE(derived4, derived4size, derived6, derived6size);

	mr_ecdh_destroy(ecdh3);
	mr_ecdh_destroy(ecdh4);
	mrclient_destroy(mr_ctx);
}