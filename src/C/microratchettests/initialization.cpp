#include "pch.h"
#include <microratchet.h>
#include "support.h"

template<size_t T>
static uint8_t emptybuffer[T] = {};

static constexpr size_t buffersize = 256;
static constexpr size_t buffersize_total = buffersize + 128;
static constexpr size_t buffersize_overhead = buffersize_total - buffersize;

#define EXPECT_NOT_EMPTY(b) EXPECT_BUFFERNE(emptybuffer<sizeof(b)>, sizeof(b), buffer, sizeof(b))
#define EXPECT_NOT_OVERFLOWED(b) \
	static_assert(sizeof(b) == buffersize_total, "invalid size"); \
	EXPECT_BUFFEREQ(emptybuffer<buffersize_overhead>, \
		buffersize_overhead, \
		b + buffersize, \
		buffersize_overhead)

#define TEST_PREAMBLE \
	uint8_t buffer[buffersize_total]{}; \
	mr_config clientcfg{ true }; \
	auto client = mr_ctx_create(&clientcfg); \
	uint8_t clientpubkey[32]; \
	auto clientidentity = mr_ecdsa_create(client); \
	ASSERT_EQ(MR_E_SUCCESS, mr_ecdsa_generate(clientidentity, clientpubkey, sizeof(clientpubkey))); \
	ASSERT_EQ(MR_E_SUCCESS, mr_ctx_set_identity(client, clientidentity, false)); \
	mr_config servercfg{ false }; \
	auto server = mr_ctx_create(&servercfg); \
	uint8_t serverpubkey[32]; \
	auto serveridentity = mr_ecdsa_create(server); \
	ASSERT_EQ(MR_E_SUCCESS, mr_ecdsa_generate(serveridentity, serverpubkey, sizeof(serverpubkey))); \
	ASSERT_EQ(MR_E_SUCCESS, mr_ctx_set_identity(server, serveridentity, false)); \
	run_on_exit _a{[client, server, clientidentity, serveridentity] { \
		mr_ctx_destroy(client); \
		mr_ctx_destroy(server); \
		mr_ecdsa_destroy(clientidentity); \
		mr_ecdsa_destroy(serveridentity); \
	}};

TEST(Initialization, ClientInitialization1) {
	TEST_PREAMBLE;

	auto result = mr_ctx_initiate_initialization(client, buffer, buffersize, false);
	ASSERT_EQ(MR_E_SENDBACK, result);

	EXPECT_NOT_EMPTY(buffer);
	EXPECT_NOT_OVERFLOWED(buffer);
}

TEST(Initialization, ClientInitialization2) {
	TEST_PREAMBLE;

	ASSERT_EQ(MR_E_SENDBACK, mr_ctx_initiate_initialization(client, buffer, buffersize, false));
	ASSERT_EQ(MR_E_SENDBACK, mr_ctx_receive(server, buffer, buffersize, buffersize, nullptr, 0));

	EXPECT_NOT_EMPTY(buffer);
	EXPECT_NOT_OVERFLOWED(buffer);
}

TEST(Initialization, ClientInitialization3) {
	TEST_PREAMBLE;

	ASSERT_EQ(MR_E_SENDBACK, mr_ctx_initiate_initialization(client, buffer, buffersize, false));
	ASSERT_EQ(MR_E_SENDBACK, mr_ctx_receive(server, buffer, buffersize, buffersize, nullptr, 0));
	ASSERT_EQ(MR_E_SENDBACK, mr_ctx_receive(client, buffer, buffersize, buffersize, nullptr, 0));

	EXPECT_NOT_EMPTY(buffer);
	EXPECT_NOT_OVERFLOWED(buffer);
}

TEST(Initialization, ClientInitialization4) {
	TEST_PREAMBLE;

	ASSERT_EQ(MR_E_SENDBACK, mr_ctx_initiate_initialization(client, buffer, buffersize, false));
	ASSERT_EQ(MR_E_SENDBACK, mr_ctx_receive(server, buffer, buffersize, buffersize, nullptr, 0));
	ASSERT_EQ(MR_E_SENDBACK, mr_ctx_receive(client, buffer, buffersize, buffersize, nullptr, 0));
	ASSERT_EQ(MR_E_SENDBACK, mr_ctx_receive(server, buffer, buffersize, buffersize, nullptr, 0));

	EXPECT_NOT_EMPTY(buffer);
	EXPECT_NOT_OVERFLOWED(buffer);
}

TEST(Initialization, ClientInitialization5) {
	TEST_PREAMBLE;

	ASSERT_EQ(MR_E_SENDBACK, mr_ctx_initiate_initialization(client, buffer, buffersize, false));
	ASSERT_EQ(MR_E_SENDBACK, mr_ctx_receive(server, buffer, buffersize, buffersize, nullptr, 0));
	ASSERT_EQ(MR_E_SENDBACK, mr_ctx_receive(client, buffer, buffersize, buffersize, nullptr, 0));
	ASSERT_EQ(MR_E_SENDBACK, mr_ctx_receive(server, buffer, buffersize, buffersize, nullptr, 0));
	ASSERT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buffer, buffersize, buffersize, nullptr, 0));

	EXPECT_NOT_EMPTY(buffer);
	EXPECT_NOT_OVERFLOWED(buffer);
}
