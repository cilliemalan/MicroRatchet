#include "pch.h"
#include <microratchet.h>
#include "support.h"

static mr_config _cfg{ 1000, 1 };

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

void  TestReference(const unsigned char* privatekey, unsigned int privatekeysize, const unsigned char* publickey, unsigned int publickeysize, const unsigned char* expected, unsigned int expectedsize)
{
	auto mr_ctx = mrclient_create(&_cfg);
	auto ecdh = mr_ecdh_create(mr_ctx);
	int r = mr_ecdsa_setprivatekey(ecdh, privatekey, privatekeysize);
	EXPECT_EQ(E_SUCCESS, r);

	unsigned char derived[32];
	unsigned int derivedsize;
	r = mr_ecdh_derivekey(ecdh, publickey, publickeysize, derived, sizeof(derived), &derivedsize);
	EXPECT_EQ(E_SUCCESS, r);
	EXPECT_BUFFEREQ(derived, derivedsize, expected, expectedsize);

	mr_ecdh_destroy(ecdh);
	mrclient_destroy(mr_ctx);
}

TEST(Ecdh, ReferenceTest1)
{
	const unsigned char pri[]{ 0x48, 0x3e, 0x29, 0x5a, 0x4c, 0xe7, 0xb1, 0x4f, 0x07, 0x77, 0x0e, 0x78, 0x00, 0xfc, 0x21, 0x98, 0x0c, 0x74, 0x2b, 0x3e, 0x29, 0x8a, 0xc8, 0x86, 0xfb, 0xf8, 0x75, 0x50, 0x75, 0x86, 0xd8, 0x47 };
	const unsigned char pub[]{ 0x27, 0x2d, 0x84, 0xff, 0x19, 0xde, 0x0b, 0x8d, 0x70, 0x2f, 0x4a, 0x79, 0x9e, 0xbd, 0xb4, 0x88, 0x1d, 0xc4, 0x71, 0x71, 0xe8, 0x1b, 0x8b, 0xc4, 0x86, 0x50, 0x53, 0x0d, 0x01, 0xfa, 0x1a, 0x6b };
	const unsigned char exp[]{ 0xe6, 0xb7, 0x57, 0x17, 0xa6, 0x3b, 0xf0, 0x79, 0x3c, 0x0e, 0x3f, 0xf7, 0x5e, 0xd9, 0xcc, 0x19, 0x19, 0x0e, 0x25, 0xfb, 0xb8, 0x53, 0xb1, 0x2b, 0xa0, 0x7b, 0x02, 0xc5, 0x6c, 0xbf, 0x78, 0x3d };
	TestReference(pri, sizeof(pri), pub, sizeof(pub), exp, sizeof(exp));
}