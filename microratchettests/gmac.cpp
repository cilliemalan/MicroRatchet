#include "pch.h"
#include <microratchet.h>
#include "support.h"

//[InlineData(new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F }, new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F }, new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F }, new byte[] { 0x2e, 0x32, 0xae, 0x56, 0x84, 0xec, 0x3b, 0x3b, 0x9e, 0x65, 0xd5, 0xf3, 0x42, 0xe1, 0x56, 0x1b })]
static mr_config _cfg{ 1000, 1, 0, 3, 10, 1, 0 };

TEST(GMac, Init) {
	auto mr_ctx = mrclient_create(&_cfg);
	auto gmac = mr_gmac_create(mr_ctx);
	const unsigned char key[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	const unsigned char iv[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

	int result = call_and_wait(mr_gmac_init, mr_ctx, gmac, key, sizeof(key), iv, sizeof(iv));
	EXPECT_EQ(E_SUCCESS, result);

	mr_gmac_destroy(gmac);
	mrclient_destroy(mr_ctx);
}

TEST(GMac, Process) {
	auto mr_ctx = mrclient_create(&_cfg);
	auto gmac = mr_gmac_create(mr_ctx);
	const unsigned char key[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	const unsigned char iv[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	const unsigned char info[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

	int result = call_and_wait(mr_gmac_init, mr_ctx, gmac, key, sizeof(key), iv, sizeof(iv));
	EXPECT_EQ(E_SUCCESS, result);

	result = call_and_wait(mr_gmac_process, mr_ctx, gmac, info, sizeof(info));
	EXPECT_EQ(E_SUCCESS, result);

	mr_gmac_destroy(gmac);
	mrclient_destroy(mr_ctx);
}

TEST(GMac, Compute) {
	auto mr_ctx = mrclient_create(&_cfg);
	auto gmac = mr_gmac_create(mr_ctx);
	const unsigned char key[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	const unsigned char iv[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	const unsigned char info[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	const unsigned char expected[] = { 0x2e, 0x32, 0xae, 0x56, 0x84, 0xec, 0x3b, 0x3b, 0x9e, 0x65, 0xd5, 0xf3, 0x42, 0xe1, 0x56, 0x1b };
	unsigned char output[16];

	int result = call_and_wait(mr_gmac_init, mr_ctx, gmac, key, sizeof(key), iv, sizeof(iv));
	EXPECT_EQ(E_SUCCESS, result);

	result = call_and_wait(mr_gmac_process, mr_ctx, gmac, info, sizeof(info));
	EXPECT_EQ(E_SUCCESS, result);

	result = call_and_wait(mr_gmac_compute, mr_ctx, gmac, output, sizeof(output));
	EXPECT_EQ(E_SUCCESS, result);

	ASSERT_BUFFEREQ(output, sizeof(output), expected, sizeof(expected));
	mr_gmac_destroy(gmac);
	mrclient_destroy(mr_ctx);
}
