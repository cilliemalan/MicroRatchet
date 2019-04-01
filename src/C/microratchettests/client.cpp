#include "pch.h"
#include <microratchet.h>

static mr_config _cfg{ 1000, 1 };

TEST(Client, Create) {
	auto mr_ctx = mrclient_create(&_cfg);
	EXPECT_NE(nullptr, mr_ctx);
	mrclient_destroy(mr_ctx);
}