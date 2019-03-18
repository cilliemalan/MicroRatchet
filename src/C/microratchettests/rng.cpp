#include "pch.h"
#include <microratchet.h>
#include "support.h"

static mr_config _cfg{ 1000, 1, 0, 3, 10, 1, 0 };

TEST(Rng, Create) {
	auto mr_ctx = mrclient_create(&_cfg);
	auto rng = mr_rng_create(mr_ctx);
	EXPECT_NE(nullptr, rng);

	mr_rng_destroy(rng);
	mrclient_destroy(mr_ctx);
}

TEST(Rng, Generate) {
	unsigned char data[32];
	memset(data, 0xCC, sizeof(data));

	auto mr_ctx = mrclient_create(&_cfg);
	auto rng = mr_rng_create(mr_ctx);
	int result = call_and_wait(mr_rng_generate, mr_ctx, rng, data, (unsigned int)sizeof(data));
	EXPECT_EQ(E_SUCCESS, result);

	bool allcc = true;
	for (auto d : data) if (d != 0xCC)
	{
		allcc = false; break;
	}
	EXPECT_FALSE(allcc);

	mr_rng_destroy(rng);
	mrclient_destroy(mr_ctx);
}

TEST(Rng, GenerateTwice) {
	unsigned char data1[32];
	unsigned char data2[32];
	memset(data1, 0xCC, sizeof(data1));
	memset(data2, 0xCC, sizeof(data2));

	auto mr_ctx = mrclient_create(&_cfg);
	auto rng = mr_rng_create(mr_ctx);
	int result = call_and_wait(mr_rng_generate, mr_ctx, rng, data1, (unsigned int)sizeof(data1));
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_rng_generate, mr_ctx, rng, data2, (unsigned int)sizeof(data2));
	EXPECT_EQ(E_SUCCESS, result);

	bool allcc = true;
	for (auto d : data1) if (d != 0xCC) { allcc = false; break; }
	EXPECT_FALSE(allcc);
	allcc = true;
	for (auto d : data2) if (d != 0xCC) { allcc = false; break; }
	EXPECT_FALSE(allcc);

	bool allsame = true;
	for (int i = 0; i < sizeof(data1); i++) if (data1[i] != data2[i]) { allsame = false; break; }
	EXPECT_FALSE(allsame);

	mr_rng_destroy(rng);
	mrclient_destroy(mr_ctx);
}

TEST(Rng, GenerateTwiceReinit) {
	unsigned char data1[32];
	unsigned char data2[32];
	memset(data1, 0xCC, sizeof(data1));
	memset(data2, 0xCC, sizeof(data2));

	auto mr_ctx = mrclient_create(&_cfg);
	auto rng1 = mr_rng_create(mr_ctx);
	auto rng2 = mr_rng_create(mr_ctx);
	int result = call_and_wait(mr_rng_generate, mr_ctx, rng1, data1, (unsigned int)sizeof(data1));
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_rng_generate, mr_ctx, rng2, data2, (unsigned int)sizeof(data2));
	EXPECT_EQ(E_SUCCESS, result);

	bool allcc = true;
	for (auto d : data1) if (d != 0xCC) { allcc = false; break; }
	EXPECT_FALSE(allcc);
	allcc = true;
	for (auto d : data2) if (d != 0xCC) { allcc = false; break; }
	EXPECT_FALSE(allcc);

	bool allsame = true;
	for (int i = 0; i < sizeof(data1); i++) if (data1[i] != data2[i]) { allsame = false; break; }
	EXPECT_FALSE(allsame);

	mr_rng_destroy(rng1);
	mr_rng_destroy(rng2);
	mrclient_destroy(mr_ctx);
}

TEST(Rng, GenerateTiny) {
	unsigned char data[1];
	memset(data, 0xCC, sizeof(data));

	auto mr_ctx = mrclient_create(&_cfg);
	auto rng = mr_rng_create(mr_ctx);
	int result = call_and_wait(mr_rng_generate, mr_ctx, rng, data, (unsigned int)sizeof(data));
	EXPECT_EQ(E_SUCCESS, result);

	mr_rng_destroy(rng);
	mrclient_destroy(mr_ctx);
}

TEST(Rng, GenerateSmall) {
	unsigned char data[4];
	memset(data, 0xCC, sizeof(data));

	auto mr_ctx = mrclient_create(&_cfg);
	auto rng = mr_rng_create(mr_ctx);
	int result = call_and_wait(mr_rng_generate, mr_ctx, rng, data, (unsigned int)sizeof(data));
	EXPECT_EQ(E_SUCCESS, result);

	bool allcc = true;
	for (auto d : data) if (d != 0xCC)
	{
		allcc = false;
		break;
	}
	EXPECT_FALSE(allcc);

	mr_rng_destroy(rng);
	mrclient_destroy(mr_ctx);
}

TEST(Rng, GenerateHuge) {
	constexpr unsigned int size = 1024 * 1024;
	unsigned char *data = new unsigned char[size];
	memset(data, 0xCC, size);

	auto mr_ctx = mrclient_create(&_cfg);
	auto rng = mr_rng_create(mr_ctx);
	int result = call_and_wait(mr_rng_generate, mr_ctx, rng, data, (unsigned int)sizeof(data));
	EXPECT_EQ(E_SUCCESS, result);

	bool allcc = true;
	for (int i = 0; i < size; i++) if (data[i] != 0xCC)
	{
		allcc = false;
		break;
	}
	EXPECT_FALSE(allcc);

	mr_rng_destroy(rng);
	mrclient_destroy(mr_ctx);
}