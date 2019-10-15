#include "pch.h"
#include <microratchet.h>
#include "support.h"

static mr_config _cfg{ true };

TEST(Rng, Create) {
	auto mr_ctx = mr_ctx_create(&_cfg);
	auto rng = mr_rng_create(mr_ctx);
	EXPECT_NE(nullptr, rng);

	mr_rng_destroy(rng);
	mr_ctx_destroy(mr_ctx);
}

TEST(Rng, Generate) {
	uint8_t data[32];
	memset(data, 0xCC, sizeof(data));

	auto mr_ctx = mr_ctx_create(&_cfg);
	auto rng = mr_rng_create(mr_ctx);
	int result = mr_rng_generate(rng, data, SIZEOF(data));
	EXPECT_EQ(E_SUCCESS, result);

	bool allcc = true;
	for (auto d : data) if (d != 0xCC)
	{
		allcc = false; break;
	}
	EXPECT_FALSE(allcc);

	mr_rng_destroy(rng);
	mr_ctx_destroy(mr_ctx);
}

TEST(Rng, GenerateTwice) {
	uint8_t data1[32];
	uint8_t data2[32];
	memset(data1, 0xCC, sizeof(data1));
	memset(data2, 0xCC, sizeof(data2));

	auto mr_ctx = mr_ctx_create(&_cfg);
	auto rng = mr_rng_create(mr_ctx);
	int result = mr_rng_generate(rng, data1, SIZEOF(data1));
	EXPECT_EQ(E_SUCCESS, result);
	result = mr_rng_generate(rng, data2, SIZEOF(data2));
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
	mr_ctx_destroy(mr_ctx);
}

TEST(Rng, GenerateTwiceReinit) {
	uint8_t data1[32];
	uint8_t data2[32];
	memset(data1, 0xCC, sizeof(data1));
	memset(data2, 0xCC, sizeof(data2));

	auto mr_ctx = mr_ctx_create(&_cfg);
	auto rng1 = mr_rng_create(mr_ctx);
	auto rng2 = mr_rng_create(mr_ctx);
	int result = mr_rng_generate(rng1, data1, SIZEOF(data1));
	EXPECT_EQ(E_SUCCESS, result);
	result = mr_rng_generate(rng2, data2, SIZEOF(data2));
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
	mr_ctx_destroy(mr_ctx);
}

TEST(Rng, GenerateTiny) {
	uint8_t data[1];
	memset(data, 0xCC, sizeof(data));

	auto mr_ctx = mr_ctx_create(&_cfg);
	auto rng = mr_rng_create(mr_ctx);
	int result = mr_rng_generate(rng, data, SIZEOF(data));
	EXPECT_EQ(E_SUCCESS, result);

	mr_rng_destroy(rng);
	mr_ctx_destroy(mr_ctx);
}

TEST(Rng, GenerateSmall) {
	uint8_t data[4];
	memset(data, 0xCC, sizeof(data));

	auto mr_ctx = mr_ctx_create(&_cfg);
	auto rng = mr_rng_create(mr_ctx);
	int result = mr_rng_generate(rng, data, SIZEOF(data));
	EXPECT_EQ(E_SUCCESS, result);

	bool allcc = true;
	for (auto d : data) if (d != 0xCC)
	{
		allcc = false;
		break;
	}
	EXPECT_FALSE(allcc);

	mr_rng_destroy(rng);
	mr_ctx_destroy(mr_ctx);
}

TEST(Rng, GenerateHuge) {
	constexpr uint32_t size = 1024 * 1024;
	uint8_t *data = new uint8_t[size];
	memset(data, 0xCC, size);

	auto mr_ctx = mr_ctx_create(&_cfg);
	auto rng = mr_rng_create(mr_ctx);
	int result = mr_rng_generate(rng, data, SIZEOF(data));
	EXPECT_EQ(E_SUCCESS, result);

	bool allcc = true;
	for (int i = 0; i < size; i++) if (data[i] != 0xCC)
	{
		allcc = false;
		break;
	}
	EXPECT_FALSE(allcc);

	mr_rng_destroy(rng);
	mr_ctx_destroy(mr_ctx);
}
