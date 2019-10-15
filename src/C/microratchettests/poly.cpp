#include "pch.h"
#include <microratchet.h>
#include "support.h"

static mr_config _cfg{ true };

TEST(Poly, Init) {
	auto mr_ctx = mr_ctx_create(&_cfg);
	auto poly = mr_poly_create(mr_ctx);
	const uint8_t key[] = {
		 0,  1,  2,  3,  4,  5,  6,  7,
		 8,  9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23,
		24, 25, 26, 27, 28, 29, 30, 31
	};
	const uint8_t iv[] = {
		 0,  1,  2,  3,  4,  5,  6,  7,
		 8,  9, 10, 11, 12, 13, 14, 15
	};

	int result = mr_poly_init(poly, key, SIZEOF(key), iv, SIZEOF(iv));
	EXPECT_EQ(MR_E_SUCCESS, result);

	mr_poly_destroy(poly);
	mr_ctx_destroy(mr_ctx);
}

TEST(Poly, Process) {
	auto mr_ctx = mr_ctx_create(&_cfg);
	auto poly = mr_poly_create(mr_ctx);
	const uint8_t key[] = {
		 0,  1,  2,  3,  4,  5,  6,  7,
		 8,  9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23,
		24, 25, 26, 27, 28, 29, 30, 31
	};
	const uint8_t iv[] = {
		 0,  1,  2,  3,  4,  5,  6,  7,
		 8,  9, 10, 11, 12, 13, 14, 15
	};
	const uint8_t info[] = {
		 0,  1,  2,  3,  4,  5,  6,  7,
		 8,  9, 10, 11, 12, 13, 14, 15
	};

	int result = mr_poly_init(poly, key, SIZEOF(key), iv, SIZEOF(iv));
	EXPECT_EQ(MR_E_SUCCESS, result);

	result = mr_poly_process(poly, info, SIZEOF(info));
	EXPECT_EQ(MR_E_SUCCESS, result);

	mr_poly_destroy(poly);
	mr_ctx_destroy(mr_ctx);
}

void computetest(
	const uint8_t* key, uint32_t keysize,
	const uint8_t* iv, uint32_t ivsize,
	const uint8_t* info, uint32_t infosize,
	const uint8_t* expected, uint32_t expectedsize)
{
	auto mr_ctx = mr_ctx_create(&_cfg);
	auto poly = mr_poly_create(mr_ctx);
	uint8_t *output = new uint8_t[expectedsize];

	int result = mr_poly_init(poly, key, keysize, iv, ivsize);
	EXPECT_EQ(MR_E_SUCCESS, result);

	result = mr_poly_process(poly, info, infosize);
	EXPECT_EQ(MR_E_SUCCESS, result);

	result = mr_poly_compute(poly, output, expectedsize);
	EXPECT_EQ(MR_E_SUCCESS, result);

	EXPECT_BUFFEREQ(output, expectedsize, expected, expectedsize);
	mr_poly_destroy(poly);
	mr_ctx_destroy(mr_ctx);
	delete[] output;
}
TEST(Poly, ReferenceTest1) {
	const uint8_t key[] = {
		0x04, 0x91, 0x6c, 0x08, 0x09, 0x31, 0x03, 0x04,
		0x05, 0x07, 0x08, 0x0c, 0x0d, 0x0f, 0x07, 0x08,
		0x91, 0x6c, 0x31, 0x88, 0x0b, 0x02, 0x03, 0x04,
		0x05, 0x07, 0x08, 0x07, 0x66, 0x4b, 0x07, 0x08
	};
	const uint8_t iv[] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
	};
	const uint8_t info[] = { 0x00 };
	const uint8_t expected[] = {
		0x0b, 0x49, 0x88, 0x1f, 0x31, 0x17, 0x1f, 0x1c,
		0xbf, 0xb3, 0x59, 0x70, 0xea, 0x1d, 0x95, 0x20
	};

	computetest(key, sizeof(key),
		iv, sizeof(iv),
		info, sizeof(info),
		expected, sizeof(expected));
}

TEST(Poly, ReferenceTest2) {
	const uint8_t key[] = {
		0x88, 0x0b, 0x0d, 0xfe, 0x91, 0x6c, 0x66, 0xd7,
		0x4b, 0x07, 0x08, 0x09, 0xfe, 0x91, 0x6c, 0x31,
		0x88, 0x0b, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08,
		0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x0d, 0x6c, 0x31
	};
	const uint8_t iv[] = {
		0x02, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
	};
	const uint8_t info[] = {
		0xd7, 0x08, 0x09, 0x08, 0x09, 0x08, 0x09, 0x6c
	};
	const uint8_t expected[] = {
		0xaa, 0xdf, 0xb0, 0xcc, 0x2f, 0xd6, 0xd8, 0x1a,
		0x24, 0x77, 0x84, 0x2c, 0x9a, 0x3b, 0x34, 0x97
	};

	computetest(key, sizeof(key),
		iv, sizeof(iv),
		info, sizeof(info),
		expected, sizeof(expected));
}

TEST(Poly, ReferenceTest3) {
	const uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x6c, 0x66, 0xd7, 0x0c, 0x0d, 0x66, 0xd7,
		0x4b, 0x07, 0x08, 0x09, 0xfe, 0x04, 0x91, 0x6c,
		0x08, 0x09, 0x0a, 0x31, 0x88, 0x0b, 0x0d, 0x04
	};
	const uint8_t iv[] = {
		0x03, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
	};
	const uint8_t info[] = {
		0x6c, 0x31, 0x88, 0x0b, 0x02, 0x07, 0x08, 0x6c,
		0x66, 0x6c, 0x08, 0x09, 0x0a, 0x31, 0x88, 0x0b,
		0x02, 0xfe, 0x04, 0x91, 0x6c, 0x08, 0xd7, 0x0c,
		0x0d, 0x66
	};
	const uint8_t expected[] = {
		0xc5, 0xe3, 0x07, 0x75, 0xf6, 0x86, 0x67, 0xd7,
		0x62, 0xdb, 0x9b, 0x7f, 0x09, 0x1c, 0xa3, 0x87
	};

	computetest(key, sizeof(key),
		iv, sizeof(iv),
		info, sizeof(info),
		expected, sizeof(expected));
}