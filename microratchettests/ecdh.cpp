#include "pch.h"
#include <microratchet.h>
#include "support.h"

static mr_config _cfg{ 1000, 1, 0, 3, 10, 1, 0 };

TEST(Ecdh, Create) {
	auto mr_ctx = mrclient_create(&_cfg);
	auto ecdh = mr_ecdh_create(mr_ctx);
	EXPECT_NE(nullptr, ecdh);

	mr_ecdh_destroy(ecdh);
	mrclient_destroy(mr_ctx);
}

TEST(Ecdh, Generate) {
	unsigned char pubkey[32];
	unsigned int pubkeysize;
	memset(pubkey, 0xCC, sizeof(pubkey));

	auto mr_ctx = mrclient_create(&_cfg);
	auto ecdh = mr_ecdh_create(mr_ctx);
	int result = call_and_wait(mr_ecdh_generate, mr_ctx, ecdh, pubkey, (unsigned int)sizeof(pubkey), &pubkeysize);
	EXPECT_EQ(E_SUCCESS, result);
	EXPECT_EQ(pubkeysize, 32);

	mr_ecdh_destroy(ecdh);
	mrclient_destroy(mr_ctx);
}
