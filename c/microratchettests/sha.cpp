#include "pch.h"
#include <microratchet.h>
#include "support.h"

static mr_config _cfg{ true };

TEST(Sha, Create) {
	auto mr_ctx = mr_ctx_create(&_cfg);
	auto sha = mr_sha_create(mr_ctx);
	EXPECT_NE(nullptr, sha);

	mr_sha_destroy(sha);
	mr_ctx_destroy(mr_ctx);
}

TEST(Sha, Init) {
	auto mr_ctx = mr_ctx_create(&_cfg);
	auto sha = mr_sha_create(mr_ctx);
	int result = mr_sha_init(sha);
	EXPECT_EQ(MR_E_SUCCESS, result);

	mr_sha_destroy(sha);
	mr_ctx_destroy(mr_ctx);
}

TEST(Sha, Process) {
	const uint8_t data[]{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

	auto mr_ctx = mr_ctx_create(&_cfg);
	auto sha = mr_sha_create(mr_ctx);
	int result = mr_sha_init(sha);
	result = mr_sha_process(sha, data, SIZEOF(data));
	EXPECT_EQ(MR_E_SUCCESS, result);

	mr_sha_destroy(sha);
	mr_ctx_destroy(mr_ctx);
}

template<uint32_t L1, uint32_t L2>
void testsha(const uint8_t (&data)[L1], const uint8_t(&expected_output)[L2])
{
	uint8_t output[32];

	auto mr_ctx = mr_ctx_create(&_cfg);
	auto sha = mr_sha_create(mr_ctx);
	int result = mr_sha_init(sha);
	EXPECT_EQ(MR_E_SUCCESS, result);
	if(sizeof(data) > 0) result = mr_sha_process(sha, data, SIZEOF(data));
	EXPECT_EQ(MR_E_SUCCESS, result);
	result = mr_sha_compute(sha, output, SIZEOF(output));
	EXPECT_EQ(MR_E_SUCCESS, result);
	EXPECT_BUFFEREQ(expected_output, sizeof(expected_output), output, sizeof(output));

	mr_sha_destroy(sha);
	mr_ctx_destroy(mr_ctx);
}

TEST(Sha, ReferenceTestEmpty) {
	uint8_t output[32];
	uint8_t expected[32]{
		0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
		0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
		0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
		0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
	};

	auto mr_ctx = mr_ctx_create(&_cfg);
	auto sha = mr_sha_create(mr_ctx);
	int result = mr_sha_init(sha);
	EXPECT_EQ(MR_E_SUCCESS, result);
	result = mr_sha_compute(sha, output, SIZEOF(output));
	EXPECT_EQ(MR_E_SUCCESS, result);
	EXPECT_BUFFEREQ(expected, sizeof(expected), output, sizeof(output));

	mr_sha_destroy(sha);
	mr_ctx_destroy(mr_ctx);
}

TEST(Sha, ReferenceTestShort1) {
	const uint8_t input[]{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	const uint8_t output[32]{
		0x66, 0x84, 0x0D, 0xDA, 0x15, 0x4E, 0x8A, 0x11,
		0x3C, 0x31, 0xDD, 0x0A, 0xD3, 0x2F, 0x7F, 0x3A,
		0x36, 0x6A, 0x80, 0xE8, 0x13, 0x69, 0x79, 0xD8,
		0xF5, 0xA1, 0x01, 0xD3, 0xD2, 0x9D, 0x6F, 0x72
	};

	testsha(input, output);
}

TEST(Sha, ReferenceTestShort2) {
	const uint8_t input[]{ 0xF1, 0x02, 0xF3, 0x04, 0xF5, 0x06, 0xF7, 0x08 };
	const uint8_t output[32]{
		0xAE, 0xB6, 0xB8, 0xE3, 0xE2, 0xF5, 0x96, 0x04,
		0xA3, 0xDD, 0x7F, 0xCC, 0xD7, 0x9A, 0x77, 0x19,
		0x81, 0x89, 0xC5, 0xCF, 0x44, 0x8C, 0x8A, 0x62,
		0x7D, 0xF8, 0x42, 0x86, 0x60, 0x4F, 0x8F, 0x7A
	};

	testsha(input, output);
}

TEST(Sha, ReferenceTestLong) {
	const uint8_t input[]{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
		0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
		0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
		0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
		0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
		0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
		0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
		0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
		0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
	};
	const uint8_t output[32]{
		0x3B, 0x7F, 0xFF, 0xD4, 0xFC, 0x0D, 0xCB, 0xD5,
		0x2D, 0xAD, 0xB0, 0xCC, 0xC6, 0xFF, 0xC3, 0x40,
		0x69, 0x67, 0x6A, 0x4A, 0x1D, 0xFD, 0x44, 0x64,
		0x57, 0xB4, 0xC9, 0xBE, 0x46, 0x04, 0xDD, 0xA1
	};

	testsha(input, output);
}


#ifdef MR_EMBEDDED
static constexpr uint32_t numshas = 1000000;
#else
static constexpr uint32_t numshas = 10000;
#endif
TEST(Sha, PerformanceTest) {
	uint8_t data[32]{
	   0x3B, 0x7F, 0xFF, 0xD4, 0xFC, 0x0D, 0xCB, 0xD5,
	   0x2D, 0xAD, 0xB0, 0xCC, 0xC6, 0xFF, 0xC3, 0x40,
	   0x69, 0x67, 0x6A, 0x4A, 0x1D, 0xFD, 0x44, 0x64,
	   0x57, 0xB4, 0xC9, 0xBE, 0x46, 0x04, 0xDD, 0xA1
	};

	auto mr_ctx = mr_ctx_create(&_cfg);
	auto sha = mr_sha_create(mr_ctx);

	auto t1 = std::chrono::high_resolution_clock::now();
	for (uint32_t i = 0; i < numshas; i++)
	{
		mr_sha_init(sha);
		mr_sha_process(sha, data, sizeof(data));
		mr_sha_compute(sha, data, sizeof(data));
	}
	auto t2 = std::chrono::high_resolution_clock::now();
	auto time_passed = std::chrono::duration_cast<std::chrono::duration<double>>(t2 - t1);
	auto seconds = time_passed.count();
	printf("Did %d hashes in %dms (%d per second)\n", numshas, (uint32_t)(seconds * 1000.0), (uint32_t)(numshas / seconds));
}
