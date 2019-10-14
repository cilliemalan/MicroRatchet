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
	auto client = mrclient_create(&clientcfg); \
	uint8_t clientpubkey[32]; \
	auto clientidentity = mr_ecdsa_create(client); \
	ASSERT_EQ(E_SUCCESS, mr_ecdsa_generate(clientidentity, clientpubkey, sizeof(clientpubkey))); \
	ASSERT_EQ(E_SUCCESS, mrclient_set_identity(client, clientidentity)); \
	mr_config servercfg{ false }; \
	auto server = mrclient_create(&servercfg); \
	uint8_t serverpubkey[32]; \
	auto serveridentity = mr_ecdsa_create(server); \
	ASSERT_EQ(E_SUCCESS, mr_ecdsa_generate(serveridentity, serverpubkey, sizeof(serverpubkey))); \
	ASSERT_EQ(E_SUCCESS, mrclient_set_identity(server, serveridentity)); \
	run_on_exit _a{[client, server, clientidentity, serveridentity] { \
		mrclient_destroy(client); \
		mrclient_destroy(server); \
		mr_ecdsa_destroy(clientidentity); \
		mr_ecdsa_destroy(serveridentity); \
	}};

#define TEST_PREAMBLE_CLIENT_SERVER TEST_PREAMBLE \
ASSERT_EQ(E_MORE, mrclient_initiate_initialization(client, buffer, buffersize, false)); \
ASSERT_EQ(E_MORE, mrclient_receive(server, buffer, buffersize, buffersize, nullptr, 0)); \
ASSERT_EQ(E_MORE, mrclient_receive(client, buffer, buffersize, buffersize, nullptr, 0)); \
ASSERT_EQ(E_MORE, mrclient_receive(server, buffer, buffersize, buffersize, nullptr, 0)); \
ASSERT_EQ(E_SUCCESS, mrclient_receive(client, buffer, buffersize, buffersize, nullptr, 0)); \

TEST(Client, Create) {
	mr_config cfg{ true };
	auto mr_ctx = mrclient_create(&cfg);
	EXPECT_NE(nullptr, mr_ctx);
	mrclient_destroy(mr_ctx);
}

TEST(Client, ClientInitialization1) {
	TEST_PREAMBLE;

	auto result = mrclient_initiate_initialization(client, buffer, buffersize, false);
	ASSERT_EQ(E_MORE, result);

	EXPECT_NOT_EMPTY(buffer);
	EXPECT_NOT_OVERFLOWED(buffer);
}

TEST(Client, ClientInitialization2) {
	TEST_PREAMBLE;

	ASSERT_EQ(E_MORE, mrclient_initiate_initialization(client, buffer, buffersize, false));
	ASSERT_EQ(E_MORE, mrclient_receive(server, buffer, buffersize, buffersize, nullptr, 0));

	EXPECT_NOT_EMPTY(buffer);
	EXPECT_NOT_OVERFLOWED(buffer);
}

TEST(Client, ClientInitialization3) {
	TEST_PREAMBLE;

	ASSERT_EQ(E_MORE, mrclient_initiate_initialization(client, buffer, buffersize, false));
	ASSERT_EQ(E_MORE, mrclient_receive(server, buffer, buffersize, buffersize, nullptr, 0));
	ASSERT_EQ(E_MORE, mrclient_receive(client, buffer, buffersize, buffersize, nullptr, 0));

	EXPECT_NOT_EMPTY(buffer);
	EXPECT_NOT_OVERFLOWED(buffer);
}

TEST(Client, ClientInitialization4) {
	TEST_PREAMBLE;

	ASSERT_EQ(E_MORE, mrclient_initiate_initialization(client, buffer, buffersize, false));
	ASSERT_EQ(E_MORE, mrclient_receive(server, buffer, buffersize, buffersize, nullptr, 0));
	ASSERT_EQ(E_MORE, mrclient_receive(client, buffer, buffersize, buffersize, nullptr, 0));
	ASSERT_EQ(E_MORE, mrclient_receive(server, buffer, buffersize, buffersize, nullptr, 0));

	EXPECT_NOT_EMPTY(buffer);
	EXPECT_NOT_OVERFLOWED(buffer);
}

TEST(Client, ClientInitialization5) {
	TEST_PREAMBLE;

	ASSERT_EQ(E_MORE, mrclient_initiate_initialization(client, buffer, buffersize, false));
	ASSERT_EQ(E_MORE, mrclient_receive(server, buffer, buffersize, buffersize, nullptr, 0));
	ASSERT_EQ(E_MORE, mrclient_receive(client, buffer, buffersize, buffersize, nullptr, 0));
	ASSERT_EQ(E_MORE, mrclient_receive(server, buffer, buffersize, buffersize, nullptr, 0));
	ASSERT_EQ(E_SUCCESS, mrclient_receive(client, buffer, buffersize, buffersize, nullptr, 0));

	EXPECT_NOT_EMPTY(buffer);
	EXPECT_NOT_OVERFLOWED(buffer);
}

TEST(Client, ClientCommunicationClientToServerWithExchange) {
	TEST_PREAMBLE_CLIENT_SERVER;

	uint8_t content[16] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	uint8_t msg[128] = {};
	memcpy(msg, content, sizeof(content));
	uint8_t* output = nullptr;
	uint32_t size = 0;

	EXPECT_EQ(E_SUCCESS, mrclient_send(client, msg, sizeof(content), sizeof(msg)));
	EXPECT_EQ(E_SUCCESS, mrclient_receive(server, msg, sizeof(msg), sizeof(msg), &output, &size));

	ASSERT_TRUE(size > sizeof(content));
	EXPECT_BUFFEREQ(content, sizeof(content), output, sizeof(content));
}

TEST(Client, ClientCommunicationServerToClientWithExchange) {
	TEST_PREAMBLE_CLIENT_SERVER;

	uint8_t content[16] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	uint8_t msg[128] = {};
	memcpy(msg, content, sizeof(content));
	uint8_t* output = nullptr;
	uint32_t size = 0;

	EXPECT_EQ(E_SUCCESS, mrclient_send(server, msg, sizeof(content), sizeof(msg)));
	EXPECT_EQ(E_SUCCESS, mrclient_receive(client, msg, sizeof(msg), sizeof(msg), &output, &size));

	ASSERT_TRUE(size > sizeof(content));
	EXPECT_BUFFEREQ(content, sizeof(content), output, sizeof(content));
}

TEST(Client, ClientCommunicationClientToServerWithoutExchange) {
	TEST_PREAMBLE_CLIENT_SERVER;

	uint8_t content[16] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	uint8_t msg[MR_MIN_MESSAGE_SIZE] = {};
	memcpy(msg, content, sizeof(content));
	uint8_t* output = nullptr;
	uint32_t size = 0;

	EXPECT_EQ(E_SUCCESS, mrclient_send(client, msg, sizeof(content), sizeof(msg)));
	EXPECT_EQ(E_SUCCESS, mrclient_receive(server, msg, sizeof(msg), sizeof(msg), &output, &size));

	ASSERT_TRUE(size == sizeof(content));
	EXPECT_BUFFEREQ(content, sizeof(content), output, sizeof(content));
}

TEST(Client, ClientCommunicationServerToClientWithoutExchange) {
	TEST_PREAMBLE_CLIENT_SERVER;

	uint8_t content[16] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	uint8_t msg[MR_MIN_MESSAGE_SIZE] = {};
	memcpy(msg, content, sizeof(content));
	uint8_t* output = nullptr;
	uint32_t size = 0;

	EXPECT_EQ(E_SUCCESS, mrclient_send(server, msg, sizeof(content), sizeof(msg)));
	EXPECT_EQ(E_SUCCESS, mrclient_receive(client, msg, sizeof(msg), sizeof(msg), &output, &size));

	ASSERT_TRUE(size == sizeof(content));
	EXPECT_BUFFEREQ(content, sizeof(content), output, sizeof(content));
}