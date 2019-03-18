#include "pch.h"
#include <microratchet.h>
#include "support.h"

static mr_config _cfg{ 1000, 1, 0, 3, 10, 1, 0 };

TEST(Ecdsa, Create) {
	auto mr_ctx = mrclient_create(&_cfg);
	auto ecdsa = mr_ecdsa_create(mr_ctx);
	EXPECT_NE(nullptr, ecdsa);

	mr_ecdsa_destroy(ecdsa);
	mrclient_destroy(mr_ctx);
}

TEST(Ecdsa, Generate) {
	unsigned char pubkey[32];
	unsigned int pubkeysize;
	memset(pubkey, 0xCC, sizeof(pubkey));

	auto mr_ctx = mrclient_create(&_cfg);
	auto ecdsa = mr_ecdsa_create(mr_ctx);
	int result = call_and_wait(mr_ecdsa_generate, mr_ctx, ecdsa, pubkey, (unsigned int)sizeof(pubkey), &pubkeysize);
	EXPECT_EQ(E_SUCCESS, result);
	EXPECT_EQ(pubkeysize, 32);

	bool allcc = true;
	for (auto d : pubkey) if (d != 0xCC)
	{
		allcc = false; break;
	}
	EXPECT_FALSE(allcc);

	mr_ecdsa_destroy(ecdsa);
	mrclient_destroy(mr_ctx);
}

TEST(Ecdsa, Sign) {
	unsigned char pubkey[32];
	unsigned int pubkeysize;
	unsigned char signature[100];
	unsigned int signaturesize;
	const unsigned char digest[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};
	memset(pubkey, 0xCC, sizeof(pubkey));
	memset(signature, 0xCC, sizeof(signature));

	auto mr_ctx = mrclient_create(&_cfg);
	auto ecdsa = mr_ecdsa_create(mr_ctx);
	int result = call_and_wait(mr_ecdsa_generate, mr_ctx, ecdsa, pubkey, (unsigned int)sizeof(pubkey), &pubkeysize);
	EXPECT_EQ(E_SUCCESS, result);

	result = call_and_wait(mr_ecdsa_sign, mr_ctx, ecdsa, digest, sizeof(digest), signature, sizeof(signature), &signaturesize);
	EXPECT_EQ(E_SUCCESS, result);
	EXPECT_EQ(64, signaturesize);

	bool allcc = true;
	bool allz = true;
	for (auto d : pubkey) if (d != 0xCC) { allcc = false; break; }
	for (auto d : pubkey) if (d != 0) { allz = false; break; }
	EXPECT_FALSE(allcc);
	EXPECT_FALSE(allz);

	mr_ecdsa_destroy(ecdsa);
	mrclient_destroy(mr_ctx);
}

TEST(Ecdsa, Verify) {
	unsigned char pubkey[32];
	unsigned int pubkeysize;
	unsigned char signature[100];
	unsigned int signaturesize;
	const unsigned char digest[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};
	memset(pubkey, 0xCC, sizeof(pubkey));
	memset(signature, 0xCC, sizeof(signature));

	auto mr_ctx = mrclient_create(&_cfg);
	auto ecdsa = mr_ecdsa_create(mr_ctx);
	int result = call_and_wait(mr_ecdsa_generate, mr_ctx, ecdsa, pubkey, (unsigned int)sizeof(pubkey), &pubkeysize);
	EXPECT_EQ(E_SUCCESS, result);

	result = call_and_wait(mr_ecdsa_sign, mr_ctx, ecdsa, digest, sizeof(digest), signature, sizeof(signature), &signaturesize);
	EXPECT_EQ(E_SUCCESS, result);

	unsigned int res;
	result = call_and_wait(mr_ecdsa_verify, mr_ctx, ecdsa, (const unsigned char*)signature, signaturesize, digest, sizeof(digest), &res);
	EXPECT_EQ(E_SUCCESS, result);
	EXPECT_EQ(1, res);

	mr_ecdsa_destroy(ecdsa);
	mrclient_destroy(mr_ctx);
}

TEST(Ecdsa, VerifyOther) {
	unsigned char pubkey[32];
	unsigned int pubkeysize;
	unsigned char signature[100];
	unsigned int signaturesize;
	const unsigned char digest[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};
	memset(pubkey, 0xCC, sizeof(pubkey));
	memset(signature, 0xCC, sizeof(signature));

	auto mr_ctx = mrclient_create(&_cfg);
	auto ecdsa = mr_ecdsa_create(mr_ctx);
	int result = call_and_wait(mr_ecdsa_generate, mr_ctx, ecdsa, pubkey, (unsigned int)sizeof(pubkey), &pubkeysize);
	EXPECT_EQ(E_SUCCESS, result);

	result = call_and_wait(mr_ecdsa_sign, mr_ctx, ecdsa, digest, sizeof(digest), signature, sizeof(signature), &signaturesize);
	EXPECT_EQ(E_SUCCESS, result);

	unsigned int res;
	result = call_and_wait(mr_ecdsa_verify_other, mr_ctx, (const unsigned char*)signature, signaturesize, (const unsigned char*)digest, sizeof(digest), (const unsigned char*)pubkey, pubkeysize, &res, mr_ctx);
	EXPECT_EQ(E_SUCCESS, result);
	EXPECT_EQ(1, res);

	mr_ecdsa_destroy(ecdsa);
	mrclient_destroy(mr_ctx);
}