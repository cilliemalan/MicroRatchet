#include "pch.h"
#include <microratchet.h>
#include "support.h"

static mr_config _cfg{ true };

TEST(Ecdsa, Create) {
	auto mr_ctx = mr_ctx_create(&_cfg);
	auto ecdsa = mr_ecdsa_create(mr_ctx);
	EXPECT_NE(nullptr, ecdsa);

	mr_ecdsa_destroy(ecdsa);
	mr_ctx_destroy(mr_ctx);
}

TEST(Ecdsa, Generate) {
	uint8_t pubkey[32];
	memset(pubkey, 0xCC, sizeof(pubkey));

	auto mr_ctx = mr_ctx_create(&_cfg);
	auto ecdsa = mr_ecdsa_create(mr_ctx);
	int result = mr_ecdsa_generate(ecdsa, pubkey, SIZEOF(pubkey));
	EXPECT_EQ(MR_E_SUCCESS, result);

	bool allcc = true;
	for (auto d : pubkey) if (d != 0xCC)
	{
		allcc = false; break;
	}
	EXPECT_FALSE(allcc);

	mr_ecdsa_destroy(ecdsa);
	mr_ctx_destroy(mr_ctx);
}

TEST(Ecdsa, Sign) {
	uint8_t pubkey[32];
	uint8_t signature[100];
	const uint8_t digest[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};
	memset(pubkey, 0xCC, sizeof(pubkey));
	memset(signature, 0xCC, sizeof(signature));

	auto mr_ctx = mr_ctx_create(&_cfg);
	auto ecdsa = mr_ecdsa_create(mr_ctx);
	int result = mr_ecdsa_generate(ecdsa, pubkey, SIZEOF(pubkey));
	EXPECT_EQ(MR_E_SUCCESS, result);

	result = mr_ecdsa_sign(ecdsa, digest, SIZEOF(digest), signature, SIZEOF(signature));
	EXPECT_EQ(MR_E_SUCCESS, result);

	bool allcc = true;
	bool allz = true;
	for (auto d : pubkey) if (d != 0xCC) { allcc = false; break; }
	for (auto d : pubkey) if (d != 0) { allz = false; break; }
	EXPECT_FALSE(allcc);
	EXPECT_FALSE(allz);

	mr_ecdsa_destroy(ecdsa);
	mr_ctx_destroy(mr_ctx);
}

TEST(Ecdsa, Verify) {
	uint8_t pubkey[32];
	uint8_t signature[64];
	const uint8_t digest[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};
	memset(pubkey, 0xCC, sizeof(pubkey));
	memset(signature, 0xCC, sizeof(signature));

	auto mr_ctx = mr_ctx_create(&_cfg);
	auto ecdsa = mr_ecdsa_create(mr_ctx);
	int result = mr_ecdsa_generate(ecdsa, pubkey, SIZEOF(pubkey));
	EXPECT_EQ(MR_E_SUCCESS, result);

	result = mr_ecdsa_sign(ecdsa, digest, SIZEOF(digest), signature, SIZEOF(signature));
	EXPECT_EQ(MR_E_SUCCESS, result);

	uint32_t res;
	result = mr_ecdsa_verify(ecdsa, (const uint8_t*)signature, SIZEOF(signature), digest, SIZEOF(digest), &res);
	EXPECT_EQ(MR_E_SUCCESS, result);
	EXPECT_EQ(true, res);

	mr_ecdsa_destroy(ecdsa);
	mr_ctx_destroy(mr_ctx);
}

TEST(Ecdsa, VerifyOther) {
	uint8_t pubkey[32];
	uint8_t signature[64];
	const uint8_t digest[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};
	memset(pubkey, 0xCC, sizeof(pubkey));
	memset(signature, 0xCC, sizeof(signature));

	auto mr_ctx = mr_ctx_create(&_cfg);
	auto ecdsa = mr_ecdsa_create(mr_ctx);
	int result = mr_ecdsa_generate(ecdsa, pubkey, SIZEOF(pubkey));
	EXPECT_EQ(MR_E_SUCCESS, result);

	result = mr_ecdsa_sign(ecdsa, digest, SIZEOF(digest), signature, SIZEOF(signature));
	EXPECT_EQ(MR_E_SUCCESS, result);

	uint32_t res;
	result = mr_ecdsa_verify_other((const uint8_t*)signature, SIZEOF(signature), (const uint8_t*)digest, SIZEOF(digest), (const uint8_t*)pubkey, SIZEOF(pubkey), &res);
	EXPECT_EQ(MR_E_SUCCESS, result);
	EXPECT_EQ(true, res);

	mr_ecdsa_destroy(ecdsa);
	mr_ctx_destroy(mr_ctx);
}

void test_verify_ecdsa(const uint8_t* pubkey, uint32_t sizeofpubkey,
	const uint8_t* digest, uint32_t sizeofdigest,
	const uint8_t* signature, uint32_t sizeofsignature)
{
	auto mr_ctx = mr_ctx_create(&_cfg);
	auto ecdsa = mr_ecdsa_create(mr_ctx);

	uint32_t res;
	int result = mr_ecdsa_verify_other(signature, sizeofsignature, digest, sizeofdigest, pubkey, sizeofpubkey, &res);
	EXPECT_EQ(MR_E_SUCCESS, result);
	EXPECT_EQ(true, res);

	mr_ecdsa_destroy(ecdsa);
	mr_ctx_destroy(mr_ctx);
}

TEST(Ecdsa, ReferenceTest1) {
	const uint8_t pubkey[32] = { 0x97, 0xb2, 0x61, 0x0a, 0x16, 0xaf, 0x92, 0x9e, 0xc6, 0x10, 0x45, 0xed, 0x8f, 0x8d, 0x22, 0x2e, 0xa8, 0x88, 0xa4, 0xdb, 0xe6, 0x45, 0x9c, 0x2a, 0x84, 0x38, 0x15, 0x63, 0x48, 0x53, 0xba, 0xbd };
	const uint8_t digest[32] = { 0xb4, 0xe2, 0xf2, 0x4c, 0x4b, 0x48, 0xc3, 0xc1, 0xd2, 0x28, 0xee, 0x92, 0x97, 0x71, 0x37, 0xc7, 0x6c, 0x47, 0x1b, 0xb3, 0x08, 0xee, 0x53, 0xdf, 0x35, 0xf8, 0x57, 0xae, 0x56, 0x59, 0xcb, 0x5b };
	const uint8_t signature[64] = { 0x95, 0x27, 0xe6, 0x66, 0x24, 0xed, 0x00, 0xda, 0xa0, 0x6a, 0xeb, 0xb6, 0x1d, 0xa0, 0x24, 0x07, 0xfe, 0x23, 0x35, 0x98, 0x9b, 0x0a, 0x97, 0xd0, 0x54, 0x82, 0x09, 0x4b, 0xd0, 0x24, 0x5f, 0x9d, 0x68, 0x34, 0x9c, 0xce, 0x79, 0x20, 0x1a, 0x26, 0xb7, 0xa9, 0x05, 0x53, 0x39, 0x0b, 0x89, 0xe0, 0x24, 0x7f, 0xac, 0x91, 0x38, 0x17, 0xed, 0xa6, 0x8d, 0x14, 0x33, 0x2f, 0x2d, 0xa3, 0x8e, 0x32 };

	test_verify_ecdsa(pubkey, sizeof(pubkey), digest, sizeof(digest), signature, sizeof(signature));
}

TEST(Ecdsa, ReferenceTest2) {
	const uint8_t pubkey[32] = { 0xe5, 0x99, 0xc5, 0x6d, 0x87, 0xc6, 0xcc, 0x10, 0x24, 0x8a, 0x50, 0x08, 0x9d, 0xa1, 0xe7, 0x56, 0x56, 0x55, 0xc6, 0xfb, 0xe4, 0x6e, 0xcc, 0x5c, 0xf0, 0x58, 0x69, 0x6a, 0x4e, 0xe9, 0xd3, 0xda };
	const uint8_t digest[32] = { 0xfe, 0xef, 0xfa, 0x56, 0x23, 0x6f, 0xe2, 0x29, 0x40, 0x4b, 0x6d, 0x9b, 0xd8, 0x7c, 0x9f, 0x48, 0xd8, 0xde, 0x72, 0xab, 0xf5, 0xe4, 0x33, 0xe9, 0x79, 0x67, 0xa8, 0x42, 0xbd, 0xa3, 0xd6, 0xb5 };
	const uint8_t signature[64] = { 0xc4, 0x21, 0x57, 0x5e, 0x11, 0xa6, 0xbc, 0x43, 0xa8, 0xe1, 0x72, 0x74, 0xf0, 0xad, 0x97, 0xd3, 0xb9, 0xef, 0xb6, 0xf9, 0xf8, 0xa6, 0xbb, 0x2b, 0x16, 0x0a, 0x96, 0xfc, 0xcd, 0x4a, 0x5e, 0xfb, 0x99, 0xb4, 0x15, 0x32, 0x3b, 0x98, 0x15, 0xaa, 0x52, 0x35, 0xaf, 0x46, 0xa3, 0x23, 0x30, 0x3b, 0x3d, 0x0e, 0x31, 0x23, 0xbb, 0x8f, 0xa8, 0x96, 0x3b, 0xa5, 0xf8, 0xd3, 0x07, 0xa2, 0x8e, 0x3d };

	test_verify_ecdsa(pubkey, sizeof(pubkey), digest, sizeof(digest), signature, sizeof(signature));
}

TEST(Ecdsa, ReferenceTest3) {
	const uint8_t pubkey[32] = { 0xe1, 0x33, 0xd0, 0x53, 0xb1, 0xc2, 0xbd, 0x7d, 0x12, 0x5a, 0x5d, 0xb0, 0x57, 0x67, 0xf3, 0xee, 0x6f, 0xa2, 0xcf, 0x55, 0xea, 0xe1, 0xbe, 0xa4, 0xd5, 0xe6, 0x86, 0x49, 0x4e, 0x88, 0x48, 0x87 };
	const uint8_t digest[32] = { 0x4d, 0x9c, 0x21, 0x03, 0x2e, 0x87, 0x13, 0x78, 0x2d, 0x54, 0x82, 0xd4, 0x85, 0xb3, 0xc3, 0xb6, 0xd2, 0x74, 0x79, 0x1f, 0x9c, 0xbc, 0xb0, 0x0b, 0x0b, 0xc1, 0x88, 0x03, 0x8d, 0xbd, 0x16, 0x51 };
	const uint8_t signature[64] = { 0x81, 0x86, 0xcc, 0x8d, 0x12, 0x67, 0xcc, 0x8b, 0x1a, 0x3b, 0x2f, 0x96, 0x6a, 0x77, 0xf6, 0xec, 0x1a, 0x73, 0xf7, 0x67, 0x02, 0xb4, 0x90, 0x10, 0x1d, 0x33, 0x66, 0x49, 0x33, 0xcb, 0xdb, 0xd4, 0x97, 0xfb, 0x40, 0x95, 0x9f, 0x17, 0xb2, 0x82, 0x88, 0x93, 0xa8, 0x84, 0x93, 0x57, 0xa5, 0xb3, 0xe6, 0x77, 0x24, 0x47, 0xc7, 0xde, 0x10, 0x9b, 0xd3, 0x0c, 0x68, 0x72, 0x85, 0x43, 0xb4, 0x48 };

	test_verify_ecdsa(pubkey, sizeof(pubkey), digest, sizeof(digest), signature, sizeof(signature));
}

TEST(Ecdsa, ReferenceTest4) {
	const uint8_t pubkey[32] = { 0x36, 0x21, 0xfc, 0xb7, 0x4b, 0x09, 0x0f, 0x95, 0x7d, 0x61, 0x53, 0xd7, 0xcb, 0x68, 0xf6, 0xbc, 0xa8, 0xb7, 0x63, 0x61, 0x34, 0xc3, 0x56, 0x72, 0x64, 0x65, 0xe2, 0x0b, 0xc7, 0xf8, 0xae, 0x70 };
	const uint8_t digest[32] = { 0x92, 0x54, 0x90, 0xaf, 0x85, 0x11, 0xae, 0xeb, 0xda, 0x8a, 0xe1, 0xc4, 0x84, 0xf0, 0x68, 0x88, 0x83, 0x9f, 0xe8, 0x1b, 0x68, 0x93, 0xa1, 0xdc, 0x20, 0xf1, 0x6d, 0xa8, 0x04, 0x91, 0x6f, 0xa3 };
	const uint8_t signature[64] = { 0xf7, 0x53, 0xc9, 0xd7, 0x84, 0x9c, 0x92, 0xce, 0xa6, 0x03, 0xc9, 0x94, 0xaa, 0x9d, 0x2b, 0x89, 0x91, 0xd6, 0x26, 0x8c, 0x12, 0xa7, 0xac, 0x9b, 0xbe, 0x33, 0x17, 0xc6, 0x68, 0xbf, 0x03, 0xc1, 0x91, 0x33, 0xb8, 0xe2, 0x86, 0x02, 0xc1, 0x2f, 0x19, 0x44, 0x96, 0xba, 0x52, 0xf6, 0xbc, 0x20, 0x98, 0x9a, 0x1c, 0xf6, 0xeb, 0x50, 0x78, 0x5e, 0xca, 0x69, 0x71, 0xb5, 0x72, 0xe5, 0x2c, 0x84 };

	test_verify_ecdsa(pubkey, sizeof(pubkey), digest, sizeof(digest), signature, sizeof(signature));
}
