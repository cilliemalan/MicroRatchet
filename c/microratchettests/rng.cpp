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
	EXPECT_EQ(MR_E_SUCCESS, result);

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
	EXPECT_EQ(MR_E_SUCCESS, result);
	result = mr_rng_generate(rng, data2, SIZEOF(data2));
	EXPECT_EQ(MR_E_SUCCESS, result);

	bool allcc = true;
	for (auto d : data1) if (d != 0xCC) { allcc = false; break; }
	EXPECT_FALSE(allcc);
	allcc = true;
	for (auto d : data2) if (d != 0xCC) { allcc = false; break; }
	EXPECT_FALSE(allcc);

	bool allsame = true;
	for (uint32_t i = 0; i < sizeof(data1); i++) if (data1[i] != data2[i]) { allsame = false; break; }
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
	EXPECT_EQ(MR_E_SUCCESS, result);
	result = mr_rng_generate(rng2, data2, SIZEOF(data2));
	EXPECT_EQ(MR_E_SUCCESS, result);

	bool allcc = true;
	for (auto d : data1) if (d != 0xCC) { allcc = false; break; }
	EXPECT_FALSE(allcc);
	allcc = true;
	for (auto d : data2) if (d != 0xCC) { allcc = false; break; }
	EXPECT_FALSE(allcc);

	bool allsame = true;
	for (uint32_t i = 0; i < sizeof(data1); i++) if (data1[i] != data2[i]) { allsame = false; break; }
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
	EXPECT_EQ(MR_E_SUCCESS, result);

	mr_rng_destroy(rng);
	mr_ctx_destroy(mr_ctx);
}

TEST(Rng, GenerateSmall) {
	uint8_t data[4];
	memset(data, 0xCC, sizeof(data));

	auto mr_ctx = mr_ctx_create(&_cfg);
	auto rng = mr_rng_create(mr_ctx);
	int result = mr_rng_generate(rng, data, SIZEOF(data));
	EXPECT_EQ(MR_E_SUCCESS, result);

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
	EXPECT_EQ(MR_E_SUCCESS, result);

	bool allcc = true;
	for (uint32_t i = 0; i < size; i++) if (data[i] != 0xCC)
	{
		allcc = false;
		break;
	}
	EXPECT_FALSE(allcc);

	mr_rng_destroy(rng);
	mr_ctx_destroy(mr_ctx);
}



#if defined(__x86_64__) || defined(_M_AMD64)
#include <immintrin.h>

static inline mr_result IntelRDseed64_r(uint64_t* rnd)
{
	for (int i = 0; i < 128; i++)
	{
		int ok = _rdseed64_step(rnd);
		if (ok == 1) return MR_E_SUCCESS;
	}
	return MR_E_RNGFAIL;
}

#endif


extern "C" mr_result mr_rng_seed(uint8_t* output, uint32_t sz)
{
#if defined(__x86_64__) || defined(_M_AMD64)

	mr_result ret;
	uint64_t rndTmp;

	for (; (sz / sizeof(uint64_t)) > 0; sz -= sizeof(uint64_t),
		output += sizeof(uint64_t)) {
		ret = IntelRDseed64_r((uint64_t*)output);
		if (ret != 0)
			return ret;
	}
	if (sz == 0) return MR_E_SUCCESS;

	/* handle unaligned remainder */
	ret = IntelRDseed64_r(&rndTmp);
	if (ret != 0) return ret;

	memcpy(output, &rndTmp, sz);
	*(volatile uint64_t*)(&rndTmp) = 0;

	return MR_E_SUCCESS;

#else

	if ((sz % 4) == 0 && (((uint32_t)output) % 4) == 0)
	{
		uint32_t* uoutput = (uint32_t*)output;
		sz /= 4;
		for (int i = 0; i < sz; i++)
		{
			uoutput[i] = rand();
		}
	}
	else
	{
		for (int i = 0; i < sz; i++)
		{
			output[i] = (uint8_t)rand();
		}
	}

	return 0;
#endif
}