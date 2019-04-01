#include "pch.h"
#include <microratchet.h>
#include "support.h"

static mr_config _cfg{ 1000, 1 };

TEST(Poly, Init) {
	auto mr_ctx = mrclient_create(&_cfg);
	auto poly = mr_poly_create(mr_ctx);
	const unsigned char key[] = {
		 0,  1,  2,  3,  4,  5,  6,  7,
		 8,  9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23,
		24, 25, 26, 27, 28, 29, 30, 31
	};

	int result = call_and_wait(mr_poly_init, mr_ctx, poly, key, (unsigned int)sizeof(key));
	EXPECT_EQ(E_SUCCESS, result);

	mr_poly_destroy(poly);
	mrclient_destroy(mr_ctx);
}

TEST(Poly, Process) {
	auto mr_ctx = mrclient_create(&_cfg);
	auto poly = mr_poly_create(mr_ctx);
	const unsigned char key[] = {
		 0,  1,  2,  3,  4,  5,  6,  7,
		 8,  9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23,
		24, 25, 26, 27, 28, 29, 30, 31
	};
	const unsigned char info[] = {
		 0,  1,  2,  3,  4,  5,  6,  7,
		 8,  9, 10, 11, 12, 13, 14, 15
	};

	int result = call_and_wait(mr_poly_init, mr_ctx, poly, key, (unsigned int)sizeof(key));
	EXPECT_EQ(E_SUCCESS, result);

	result = call_and_wait(mr_poly_process, mr_ctx, poly, info, (unsigned int)sizeof(info));
	EXPECT_EQ(E_SUCCESS, result);

	mr_poly_destroy(poly);
	mrclient_destroy(mr_ctx);
}

void computetest(
	const unsigned char* key, unsigned int keysize,
	const unsigned char* info, unsigned int infosize,
	const unsigned char* expected, unsigned int expectedsize)
{
	auto mr_ctx = mrclient_create(&_cfg);
	auto poly = mr_poly_create(mr_ctx);
	unsigned char *output = new unsigned char[expectedsize];

	int result = call_and_wait(mr_poly_init, mr_ctx, poly, key, keysize);
	EXPECT_EQ(E_SUCCESS, result);

	result = call_and_wait(mr_poly_process, mr_ctx, poly, info, infosize);
	EXPECT_EQ(E_SUCCESS, result);

	result = call_and_wait(mr_poly_compute, mr_ctx, poly, output, expectedsize);
	EXPECT_EQ(E_SUCCESS, result);

	EXPECT_BUFFEREQ(output, expectedsize, expected, expectedsize);
	mr_poly_destroy(poly);
	mrclient_destroy(mr_ctx);
	delete[] output;
}

TEST(Poly, Compute1) {
	const unsigned char key[] = {
		0x04, 0x91, 0x6c, 0x08, 0x09, 0x31, 0x03, 0x04,
		0x05, 0x07, 0x08, 0x0c, 0x0d, 0x0f, 0x07, 0x08,
		0x91, 0x6c, 0x31, 0x88, 0x0b, 0x02, 0x03, 0x04,
		0x05, 0x07, 0x08, 0x07, 0x66, 0x4b, 0x07, 0x08
	};
	const unsigned char info[] = { 0x00 };
	const unsigned char expected[] = {
		0x9b, 0x70, 0xc2, 0xf4, 0x13, 0x0a, 0x34, 0x07,
		0x09, 0x0b, 0x0f, 0x0f, 0x72, 0x57, 0x16, 0x0f
	};

	computetest(key, sizeof(key),
		info, sizeof(info),
		expected, sizeof(expected));
}

TEST(Poly, Compute2) {
	const unsigned char key[] = {
		0x88, 0x0b, 0x0d, 0xfe, 0x91, 0x6c, 0x66, 0xd7,
		0x4b, 0x07, 0x08, 0x09, 0xfe, 0x91, 0x6c, 0x31,
		0x88, 0x0b, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08,
		0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x0d, 0x6c, 0x31
	};
	const unsigned char info[] = {
		0xd7, 0x08, 0x09, 0x08, 0x09, 0x08, 0x09, 0x6c
	};
	const unsigned char expected[] = {
		0xc1, 0x35, 0x43, 0x8c, 0x94, 0x48, 0x13, 0x75,
		0x1f, 0x3d, 0xd3, 0x81, 0x30, 0x80, 0xdf, 0x07 };

	computetest(key, sizeof(key),
		info, sizeof(info),
		expected, sizeof(expected));
}

TEST(Poly, Compute3) {
	const unsigned char key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x6c, 0x66, 0xd7, 0x0c, 0x0d, 0x66, 0xd7,
		0x4b, 0x07, 0x08, 0x09, 0xfe, 0x04, 0x91, 0x6c,
		0x08, 0x09, 0x0a, 0x31, 0x88, 0x0b, 0x0d, 0x04
	};
	const unsigned char info[] = {
		0x6c, 0x31, 0x88, 0x0b, 0x02, 0x07, 0x08, 0x6c,
		0x66, 0x6c, 0x08, 0x09, 0x0a, 0x31, 0x88, 0x0b,
		0x02, 0xfe, 0x04, 0x91, 0x6c, 0x08, 0xd7, 0x0c,
		0x0d, 0x66
	};
	const unsigned char expected[] = {
		0xd4, 0xa4, 0x13, 0xed, 0xa4, 0x5f, 0xac, 0x6b,
		0x0a, 0xa1, 0x3f, 0xa7, 0x94, 0xa1, 0x26, 0x80
	};

	computetest(key, sizeof(key),
		info, sizeof(info),
		expected, sizeof(expected));
}