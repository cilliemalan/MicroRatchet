#include "pch.h"
#include <microratchet.h>

static mr_config _cfg{ true };

TEST(Client, Create) {
	auto mr_ctx = mrclient_create(&_cfg);
	EXPECT_NE(nullptr, mr_ctx);
	mrclient_destroy(mr_ctx);
}