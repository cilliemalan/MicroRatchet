#include "pch.h"
#include <microratchet.h>
#include "support.h"

static mr_config _cfg{ 1000, 1, 0, 3, 10, 1, 0 };

TEST(Aes, Create) {
	auto mr_ctx = mrclient_create(&_cfg);
	auto aes = mr_aes_create(mr_ctx);
	EXPECT_NE(nullptr, aes);

	mr_aes_destroy(aes);
	mrclient_destroy(mr_ctx);
}

TEST(Aes, Init256) {
	const unsigned char key[]{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	};
	const unsigned char iv[]{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};

	auto mr_ctx = mrclient_create(&_cfg);
	auto aes = mr_aes_create(mr_ctx);
	EXPECT_NE(nullptr, aes);
	int result = call_and_wait(mr_aes_init, mr_ctx, aes, key, (unsigned int)sizeof(key), iv, (unsigned int)sizeof(iv));
	EXPECT_EQ(E_SUCCESS, result);

	mr_aes_destroy(aes);
	mrclient_destroy(mr_ctx);
}

TEST(Aes, Init128) {
	const unsigned char key[]{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};
	const unsigned char iv[]{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};

	auto mr_ctx = mrclient_create(&_cfg);
	auto aes = mr_aes_create(mr_ctx);
	EXPECT_NE(nullptr, aes);
	int result = call_and_wait(mr_aes_init, mr_ctx, aes, key, (unsigned int)sizeof(key), iv, (unsigned int)sizeof(iv));
	EXPECT_EQ(E_SUCCESS, result);

	mr_aes_destroy(aes);
	mrclient_destroy(mr_ctx);
}

TEST(Aes, Process256) {
	const unsigned char key[]{
		0x07, 0x45, 0x19, 0x3f, 0x99, 0x2f, 0x6f, 0x7e,
		0xa2, 0xfb, 0x7d, 0xdb, 0xa0, 0x82, 0x85, 0x71,
		0xdc, 0xc9, 0x8c, 0xb5, 0x82, 0xdd, 0x05, 0xe1,
		0xd0, 0x26, 0x57, 0x7a, 0x92, 0xb1, 0x56, 0x99
	};
	const unsigned char iv[]{
		0x07, 0x45, 0x19, 0x3f, 0x99, 0x2f, 0x6f, 0x7e,
		0xa2, 0xfb, 0x7d, 0xdb, 0xa0, 0x82, 0x85, 0x71
	};
	const unsigned char input[]{
		1, 2, 3, 4, 5, 6, 7, 8
	};
	unsigned char output[8];
	const unsigned char expected[]{
		0xe4, 0x9e, 0xbb, 0xd9, 0xa7, 0x0e, 0x5b, 0xa1
	};

	auto mr_ctx = mrclient_create(&_cfg);
	auto aes = mr_aes_create(mr_ctx);
	EXPECT_NE(nullptr, aes);
	int result = call_and_wait(mr_aes_init, mr_ctx, aes, key, (unsigned int)sizeof(key), iv, (unsigned int)sizeof(iv));
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_aes_process, mr_ctx, aes, input, (unsigned int)sizeof(input), output, (unsigned int)sizeof(output));
	EXPECT_EQ(E_SUCCESS, result);
	EXPECT_BUFFEREQ(output, sizeof(output), expected, sizeof(expected));

	mr_aes_destroy(aes);
	mrclient_destroy(mr_ctx);
}

TEST(Aes, Process256Reverse) {
	const unsigned char key[]{
		0x07, 0x45, 0x19, 0x3f, 0x99, 0x2f, 0x6f, 0x7e,
		0xa2, 0xfb, 0x7d, 0xdb, 0xa0, 0x82, 0x85, 0x71,
		0xdc, 0xc9, 0x8c, 0xb5, 0x82, 0xdd, 0x05, 0xe1,
		0xd0, 0x26, 0x57, 0x7a, 0x92, 0xb1, 0x56, 0x99
	};
	const unsigned char iv[]{
		0x07, 0x45, 0x19, 0x3f, 0x99, 0x2f, 0x6f, 0x7e,
		0xa2, 0xfb, 0x7d, 0xdb, 0xa0, 0x82, 0x85, 0x71
	};
	const unsigned char expected[]{
		1, 2, 3, 4, 5, 6, 7, 8
	};
	unsigned char output[8];
	const unsigned char input[]{
		0xe4, 0x9e, 0xbb, 0xd9, 0xa7, 0x0e, 0x5b, 0xa1
	};

	auto mr_ctx = mrclient_create(&_cfg);
	auto aes = mr_aes_create(mr_ctx);
	EXPECT_NE(nullptr, aes);
	int result = call_and_wait(mr_aes_init, mr_ctx, aes, key, (unsigned int)sizeof(key), iv, (unsigned int)sizeof(iv));
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_aes_process, mr_ctx, aes, input, (unsigned int)sizeof(input), output, (unsigned int)sizeof(output));
	EXPECT_EQ(E_SUCCESS, result);
	EXPECT_BUFFEREQ(output, sizeof(output), expected, sizeof(expected));

	mr_aes_destroy(aes);
	mrclient_destroy(mr_ctx);
}

TEST(Aes, Process128) {
	const unsigned char key[]{
		0x06, 0x19, 0x3f, 0x99, 0x2f, 0xdc, 0xc9, 0x8c,
		0xb5, 0x82, 0xdd, 0x05, 0xe1, 0xd0, 0x26, 0x99
	};
	const unsigned char iv[]{
		0x07, 0x45, 0x19, 0x3f, 0x99, 0x2f, 0x6f, 0x7e,
		0xa2, 0xfb, 0x7d, 0xdb, 0xa0, 0x82, 0x85, 0x71
	};
	const unsigned char input[]{
		1, 2, 3, 4, 5, 6, 7, 8
	};
	unsigned char output[8];
	const unsigned char expected[]{
		0x3b, 0xb0, 0xc2, 0x70, 0x83, 0x14, 0x09, 0x29
	};

	auto mr_ctx = mrclient_create(&_cfg);
	auto aes = mr_aes_create(mr_ctx);
	EXPECT_NE(nullptr, aes);
	int result = call_and_wait(mr_aes_init, mr_ctx, aes, key, (unsigned int)sizeof(key), iv, (unsigned int)sizeof(iv));
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_aes_process, mr_ctx, aes, input, (unsigned int)sizeof(input), output, (unsigned int)sizeof(output));
	EXPECT_EQ(E_SUCCESS, result);
	EXPECT_BUFFEREQ(output, sizeof(output), expected, sizeof(expected));

	mr_aes_destroy(aes);
	mrclient_destroy(mr_ctx);
}

TEST(Aes, Process128Reverse) {
	const unsigned char key[]{
		0x06, 0x19, 0x3f, 0x99, 0x2f, 0xdc, 0xc9, 0x8c,
		0xb5, 0x82, 0xdd, 0x05, 0xe1, 0xd0, 0x26, 0x99
	};
	const unsigned char iv[]{
		0x07, 0x45, 0x19, 0x3f, 0x99, 0x2f, 0x6f, 0x7e,
		0xa2, 0xfb, 0x7d, 0xdb, 0xa0, 0x82, 0x85, 0x71
	};
	const unsigned char expected[]{
		1, 2, 3, 4, 5, 6, 7, 8
	};
	unsigned char output[8];
	const unsigned char input[]{
		0x3b, 0xb0, 0xc2, 0x70, 0x83, 0x14, 0x09, 0x29
	};

	auto mr_ctx = mrclient_create(&_cfg);
	auto aes = mr_aes_create(mr_ctx);
	EXPECT_NE(nullptr, aes);
	int result = call_and_wait(mr_aes_init, mr_ctx, aes, key, (unsigned int)sizeof(key), iv, (unsigned int)sizeof(iv));
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_aes_process, mr_ctx, aes, input, (unsigned int)sizeof(input), output, (unsigned int)sizeof(output));
	EXPECT_EQ(E_SUCCESS, result);
	EXPECT_BUFFEREQ(output, sizeof(output), expected, sizeof(expected));

	mr_aes_destroy(aes);
	mrclient_destroy(mr_ctx);
}

TEST(Aes, ProcessBlank256) {
	const unsigned char key[]{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	const unsigned char iv[]{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	const unsigned char input[]{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	unsigned char output[8];
	const unsigned char expected[]{
		0x93, 0xb7, 0x9c, 0xc9, 0xea, 0x34, 0x75, 0x62
	};

	auto mr_ctx = mrclient_create(&_cfg);
	auto aes = mr_aes_create(mr_ctx);
	EXPECT_NE(nullptr, aes);
	int result = call_and_wait(mr_aes_init, mr_ctx, aes, key, (unsigned int)sizeof(key), iv, (unsigned int)sizeof(iv));
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_aes_process, mr_ctx, aes, input, (unsigned int)sizeof(input), output, (unsigned int)sizeof(output));
	EXPECT_EQ(E_SUCCESS, result);
	EXPECT_BUFFEREQ(output, sizeof(output), expected, sizeof(expected));

	mr_aes_destroy(aes);
	mrclient_destroy(mr_ctx);
}

TEST(Aes, ProcessBlank128) {
	const unsigned char key[]{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	const unsigned char iv[]{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	const unsigned char input[]{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char output[8];
	const unsigned char expected[]{
		0xf4, 0x08, 0x54, 0x3a, 0x9b, 0x0e, 0xf0, 0xce
	};

	auto mr_ctx = mrclient_create(&_cfg);
	auto aes = mr_aes_create(mr_ctx);
	EXPECT_NE(nullptr, aes);
	int result = call_and_wait(mr_aes_init, mr_ctx, aes, key, (unsigned int)sizeof(key), iv, (unsigned int)sizeof(iv));
	EXPECT_EQ(E_SUCCESS, result);
	result = call_and_wait(mr_aes_process, mr_ctx, aes, input, (unsigned int)sizeof(input), output, (unsigned int)sizeof(output));
	EXPECT_EQ(E_SUCCESS, result);
	EXPECT_BUFFEREQ(output, sizeof(output), expected, sizeof(expected));

	mr_aes_destroy(aes);
	mrclient_destroy(mr_ctx);
}

