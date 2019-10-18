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
	mr_rng_ctx rng = mr_rng_create(client); \
	uint8_t clientpubkey[32]; \
	auto clientidentity = mr_ecdsa_create(client); \
	ASSERT_EQ(MR_E_SUCCESS, mr_ecdsa_generate(clientidentity, clientpubkey, sizeof(clientpubkey))); \
	ASSERT_EQ(MR_E_SUCCESS, mr_ctx_set_identity(client, clientidentity)); \
	mr_config servercfg{ false }; \
	auto server = mr_ctx_create(&servercfg); \
	uint8_t serverpubkey[32]; \
	auto serveridentity = mr_ecdsa_create(server); \
	ASSERT_EQ(MR_E_SUCCESS, mr_ecdsa_generate(serveridentity, serverpubkey, sizeof(serverpubkey))); \
	ASSERT_EQ(MR_E_SUCCESS, mr_ctx_set_identity(server, serveridentity)); \
	run_on_exit _a{[=] { \
		mr_rng_destroy(rng); \
		mr_ctx_destroy(client); \
		mr_ctx_destroy(server); \
		mr_ecdsa_destroy(clientidentity); \
		mr_ecdsa_destroy(serveridentity); \
	}};

#define TEST_PREAMBLE_CLIENT_SERVER \
TEST_PREAMBLE \
ASSERT_EQ(MR_E_SENDBACK, mr_ctx_initiate_initialization(client, buffer, buffersize, false)); \
ASSERT_EQ(MR_E_SENDBACK, mr_ctx_receive(server, buffer, buffersize, buffersize, nullptr, 0)); \
ASSERT_EQ(MR_E_SENDBACK, mr_ctx_receive(client, buffer, buffersize, buffersize, nullptr, 0)); \
ASSERT_EQ(MR_E_SENDBACK, mr_ctx_receive(server, buffer, buffersize, buffersize, nullptr, 0)); \
ASSERT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buffer, buffersize, buffersize, nullptr, 0)); \

#define RANDOMDATA(variable, howmuch) uint8_t variable[howmuch]; mr_rng_generate(rng, variable, sizeof(variable));

TEST(Context, Create) {
	mr_config cfg{ true };
	auto mr_ctx = mr_ctx_create(&cfg);
	EXPECT_NE(nullptr, mr_ctx);
	mr_ctx_destroy(mr_ctx);
}

TEST(Context, ClientCommunicationClientToServerWithExchange) {
	TEST_PREAMBLE_CLIENT_SERVER;

	RANDOMDATA(content, 16);
	uint8_t msg[128] = {};
	memcpy(msg, content, sizeof(content));
	uint8_t* output = nullptr;
	uint32_t size = 0;

	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, msg, sizeof(content), sizeof(msg)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, msg, sizeof(msg), sizeof(msg), &output, &size));

	ASSERT_TRUE(size > sizeof(content));
	EXPECT_BUFFEREQ(content, sizeof(content), output, sizeof(content));
}

TEST(Context, ClientCommunicationServerToClientWithExchange) {
	TEST_PREAMBLE_CLIENT_SERVER;

	RANDOMDATA(content, 16);
	uint8_t msg[128] = {};
	memcpy(msg, content, sizeof(content));
	uint8_t* output = nullptr;
	uint32_t size = 0;

	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, msg, sizeof(content), sizeof(msg)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, msg, sizeof(msg), sizeof(msg), &output, &size));

	ASSERT_TRUE(size > sizeof(content));
	EXPECT_BUFFEREQ(content, sizeof(content), output, sizeof(content));
}

TEST(Context, ClientCommunicationClientToServerWithoutExchange) {
	TEST_PREAMBLE_CLIENT_SERVER;

	RANDOMDATA(content, 16);
	uint8_t msg[MR_MIN_MESSAGE_SIZE] = {};
	memcpy(msg, content, sizeof(content));
	uint8_t* output = nullptr;
	uint32_t size = 0;

	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, msg, sizeof(content), sizeof(msg)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, msg, sizeof(msg), sizeof(msg), &output, &size));

	ASSERT_TRUE(size == sizeof(content));
	EXPECT_BUFFEREQ(content, sizeof(content), output, sizeof(content));
}

TEST(Context, ClientCommunicationServerToClientWithoutExchange) {
	TEST_PREAMBLE_CLIENT_SERVER;

	RANDOMDATA(content, 16);
	uint8_t msg[MR_MIN_MESSAGE_SIZE] = {};
	memcpy(msg, content, sizeof(content));
	uint8_t* output = nullptr;
	uint32_t size = 0;

	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, msg, sizeof(content), sizeof(msg)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, msg, sizeof(msg), sizeof(msg), &output, &size));

	ASSERT_TRUE(size == sizeof(content));
	EXPECT_BUFFEREQ(content, sizeof(content), output, sizeof(content));
}

TEST(Context, OneMessageClientServer) {
	TEST_PREAMBLE_CLIENT_SERVER;

	RANDOMDATA(msg1, 32);

	uint8_t buff[128] = {};
	uint8_t* payload = 0;
	uint32_t payloadsize = 0;

	memcpy(buff, msg1, sizeof(msg1));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, sizeof(msg1), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg1, sizeof(msg1), payload, sizeof(msg1));
}

TEST(Context, OneMessageServerClient) {
	TEST_PREAMBLE_CLIENT_SERVER;

	RANDOMDATA(msg1, 32);

	uint8_t buff[128] = {};
	uint8_t* payload = 0;
	uint32_t payloadsize = 0;

	memcpy(buff, msg1, sizeof(msg1));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, sizeof(msg1), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg1, sizeof(msg1), payload, sizeof(msg1));
}

TEST(Context, MultiMessagesClientServerNoReply) {
	TEST_PREAMBLE_CLIENT_SERVER;

	RANDOMDATA(msg1, 32);
	RANDOMDATA(msg2, 32);
	RANDOMDATA(msg3, 32);

	uint8_t buff[128] = {};
	uint8_t* payload = 0;
	uint32_t payloadsize = 0;

	memcpy(buff, msg1, sizeof(msg1));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, sizeof(msg1), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg1, sizeof(msg1), payload, sizeof(msg1));

	memcpy(buff, msg2, sizeof(msg2));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, sizeof(msg2), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg2, sizeof(msg2), payload, sizeof(msg2));

	memcpy(buff, msg3, sizeof(msg3));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, sizeof(msg3), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg3, sizeof(msg3), payload, sizeof(msg3));
}

TEST(Context, MultiMessagesServerClientNoReply) {
	TEST_PREAMBLE_CLIENT_SERVER;

	RANDOMDATA(msg1, 32);
	RANDOMDATA(msg2, 32);
	RANDOMDATA(msg3, 32);

	uint8_t buff[128] = {};
	uint8_t* payload = 0;
	uint32_t payloadsize = 0;

	memcpy(buff, msg1, sizeof(msg1));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, sizeof(msg1), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg1, sizeof(msg1), payload, sizeof(msg1));

	memcpy(buff, msg2, sizeof(msg2));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, sizeof(msg2), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg2, sizeof(msg2), payload, sizeof(msg2));

	memcpy(buff, msg3, sizeof(msg3));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, sizeof(msg3), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg3, sizeof(msg3), payload, sizeof(msg3));
}

TEST(Context, MultiMessages) {
	TEST_PREAMBLE_CLIENT_SERVER;

	RANDOMDATA(msg1, 32);
	RANDOMDATA(msg2, 32);
	RANDOMDATA(msg3, 32);
	RANDOMDATA(msg4, 32);
	RANDOMDATA(msg5, 32);
	RANDOMDATA(msg6, 32);

	uint8_t buff[128] = {};
	uint8_t* payload = 0;
	uint32_t payloadsize = 0;

	memcpy(buff, msg1, sizeof(msg1));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, sizeof(msg1), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg1, sizeof(msg1), payload, sizeof(msg1));

	memcpy(buff, msg2, sizeof(msg2));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, sizeof(msg2), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg2, sizeof(msg2), payload, sizeof(msg2));

	memcpy(buff, msg3, sizeof(msg3));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, sizeof(msg3), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg3, sizeof(msg3), payload, sizeof(msg3));

	memcpy(buff, msg4, sizeof(msg4));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, sizeof(msg4), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg4, sizeof(msg4), payload, sizeof(msg4));

	memcpy(buff, msg5, sizeof(msg5));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, sizeof(msg5), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg5, sizeof(msg5), payload, sizeof(msg5));

	memcpy(buff, msg6, sizeof(msg6));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, sizeof(msg6), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg6, sizeof(msg6), payload, sizeof(msg6));
}

TEST(Context, MultiMessagesInterleaved) {
	TEST_PREAMBLE_CLIENT_SERVER;

	RANDOMDATA(msg1, 32);
	RANDOMDATA(msg2, 32);
	RANDOMDATA(msg3, 32);
	RANDOMDATA(msg4, 32);
	RANDOMDATA(msg5, 32);
	RANDOMDATA(msg6, 32);

	uint8_t buff[128] = {};
	uint8_t* payload = 0;
	uint32_t payloadsize = 0;

	memcpy(buff, msg1, sizeof(msg1));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, sizeof(msg1), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg1, sizeof(msg1), payload, sizeof(msg1));

	memcpy(buff, msg2, sizeof(msg2));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, sizeof(msg2), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg2, sizeof(msg2), payload, sizeof(msg2));

	memcpy(buff, msg3, sizeof(msg3));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, sizeof(msg3), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg3, sizeof(msg3), payload, sizeof(msg3));

	memcpy(buff, msg4, sizeof(msg4));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, sizeof(msg4), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg4, sizeof(msg4), payload, sizeof(msg4));

	memcpy(buff, msg5, sizeof(msg5));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, sizeof(msg5), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg5, sizeof(msg5), payload, sizeof(msg5));

	memcpy(buff, msg6, sizeof(msg6));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, sizeof(msg6), sizeof(buff)));
	EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
	ASSERT_BUFFEREQ(msg6, sizeof(msg6), payload, sizeof(msg6));
}

TEST(Context, MultiMessagesManyServerClient) {
	TEST_PREAMBLE_CLIENT_SERVER;

	uint8_t msg[32] = {};
	uint8_t buff[128] = {};
	uint8_t* payload = 0;
	uint32_t payloadsize = 0;

	for (int i = 0; i < 100; i++)
	{
		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg, sizeof(msg)));
		memcpy(buff, msg, sizeof(msg));
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, sizeof(msg), sizeof(buff)));
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
		ASSERT_BUFFEREQ(msg, sizeof(msg), payload, sizeof(msg));
	}
}

TEST(Context, MultiMessagesManyClientServer) {
	TEST_PREAMBLE_CLIENT_SERVER;

	uint8_t msg[32] = {};
	uint8_t buff[128] = {};
	uint8_t* payload = 0;
	uint32_t payloadsize = 0;

	for (int i = 0; i < 100; i++)
	{
		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg, sizeof(msg)));
		memcpy(buff, msg, sizeof(msg));
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, sizeof(msg), sizeof(buff)));
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
		ASSERT_BUFFEREQ(msg, sizeof(msg), payload, sizeof(msg));
	}
}

TEST(Context, MultiMessagesManyInterleaved) {
	TEST_PREAMBLE_CLIENT_SERVER;

	uint8_t msg[32] = {};
	uint8_t buff[128] = {};
	uint8_t* payload = 0;
	uint32_t payloadsize = 0;

	for (int i = 0; i < 50; i++)
	{
		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg, sizeof(msg)));
		memcpy(buff, msg, sizeof(msg));
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, sizeof(msg), sizeof(buff)));
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
		ASSERT_BUFFEREQ(msg, sizeof(msg), payload, sizeof(msg));

		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg, sizeof(msg)));
		memcpy(buff, msg, sizeof(msg));
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, sizeof(msg), sizeof(buff)));
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
		ASSERT_BUFFEREQ(msg, sizeof(msg), payload, sizeof(msg));
	}
}

TEST(Context, MultiMessagesManyInterleavedLargeMessages) {
	TEST_PREAMBLE_CLIENT_SERVER;

	uint8_t buff[128] = {};
	uint8_t msg[sizeof(buff) - MR_OVERHEAD_WITHOUT_ECDH] = {};
	uint8_t* payload = 0;
	uint32_t payloadsize = 0;

	for (int i = 0; i < 50; i++)
	{
		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg, sizeof(msg)));
		memcpy(buff, msg, sizeof(msg));
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, sizeof(msg), sizeof(buff)));
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
		ASSERT_BUFFEREQ(msg, sizeof(msg), payload, sizeof(msg));

		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg, sizeof(msg)));
		memcpy(buff, msg, sizeof(msg));
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, sizeof(msg), sizeof(buff)));
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
		ASSERT_BUFFEREQ(msg, sizeof(msg), payload, sizeof(msg));
	}
}

TEST(Context, MultiMessagesManyInterleavedRandomSize) {
	TEST_PREAMBLE_CLIENT_SERVER;

	uint8_t buff[128] = {};
	constexpr uint32_t smallmsg = sizeof(buff) - MR_OVERHEAD_WITH_ECDH;
	constexpr uint32_t largemsg = sizeof(buff) - MR_OVERHEAD_WITHOUT_ECDH;
	uint8_t msg[largemsg] = {};
	uint8_t* payload = 0;
	uint32_t payloadsize = 0;
	uint32_t msgsize = 0;

	for (int i = 0; i < 50; i++)
	{
		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg, sizeof(msg)));
		msgsize = msg[0] < 128 ? largemsg : smallmsg;
		memcpy(buff, msg, msgsize);
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, msgsize, sizeof(buff)));
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
		ASSERT_BUFFEREQ(msg, msgsize, payload, msgsize);

		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg, sizeof(msg)));
		msgsize = msg[0] < 128 ? largemsg : smallmsg;
		memcpy(buff, msg, msgsize);
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, msgsize, sizeof(buff)));
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
		ASSERT_BUFFEREQ(msg, msgsize, payload, msgsize);
	}
}

TEST(Context, MultiMessagesManyInterleavedRandomSizeWithDrops10Percent) {
	TEST_PREAMBLE_CLIENT_SERVER;

	uint8_t buff[128] = {};
	constexpr uint32_t smallmsg = sizeof(buff) - MR_OVERHEAD_WITH_ECDH;
	constexpr uint32_t largemsg = sizeof(buff) - MR_OVERHEAD_WITHOUT_ECDH;
	uint8_t msg[largemsg] = {};
	uint8_t* payload = 0;
	uint32_t payloadsize = 0;
	uint32_t msgsize = 0;
	bool drop = false;

	for (int i = 0; i < 50; i++)
	{
		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg, sizeof(msg)));
		msgsize = msg[0] < 128 ? largemsg : smallmsg;
		drop = msg[1] < 25;
		memcpy(buff, msg, msgsize);
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, msgsize, sizeof(buff)));
		if (!drop)
		{
			EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
			ASSERT_BUFFEREQ(msg, msgsize, payload, msgsize);
		}

		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg, sizeof(msg)));
		msgsize = msg[0] < 128 ? largemsg : smallmsg;
		drop = msg[1] < 25;
		memcpy(buff, msg, msgsize);
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, msgsize, sizeof(buff)));
		if (!drop)
		{
			EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
			ASSERT_BUFFEREQ(msg, msgsize, payload, msgsize);
		}
	}
}

TEST(Context, MultiMessagesManyInterleavedRandomSizeWithDrops50Percent) {
	TEST_PREAMBLE_CLIENT_SERVER;

	uint8_t buff[128] = {};
	constexpr uint32_t smallmsg = sizeof(buff) - MR_OVERHEAD_WITH_ECDH;
	constexpr uint32_t largemsg = sizeof(buff) - MR_OVERHEAD_WITHOUT_ECDH;
	uint8_t msg[largemsg] = {};
	uint8_t* payload = 0;
	uint32_t payloadsize = 0;
	uint32_t msgsize = 0;
	bool drop = false;

	for (int i = 0; i < 50; i++)
	{
		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg, sizeof(msg)));
		msgsize = msg[0] < 128 ? largemsg : smallmsg;
		drop = msg[1] < 128;
		memcpy(buff, msg, msgsize);
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, msgsize, sizeof(buff)));
		if (!drop)
		{
			EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
			ASSERT_BUFFEREQ(msg, msgsize, payload, msgsize);
		}

		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg, sizeof(msg)));
		msgsize = msg[0] < 128 ? largemsg : smallmsg;
		drop = msg[1] < 128;
		memcpy(buff, msg, msgsize);
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, msgsize, sizeof(buff)));
		if (!drop)
		{
			EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
			ASSERT_BUFFEREQ(msg, msgsize, payload, msgsize);
		}
	}
}

TEST(Context, MultiMessagesManyInterleavedRandomSizeWithCorruption10Percent) {
	TEST_PREAMBLE_CLIENT_SERVER;

	uint8_t buff[128] = {};
	constexpr uint32_t smallmsg = sizeof(buff) - MR_OVERHEAD_WITH_ECDH;
	constexpr uint32_t largemsg = sizeof(buff) - MR_OVERHEAD_WITHOUT_ECDH;
	uint8_t msg[largemsg] = {};
	uint8_t* payload = 0;
	uint32_t payloadsize = 0;
	uint32_t msgsize = 0;
	bool corrupt = false;

	for (int i = 0; i < 50; i++)
	{
		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg, sizeof(msg)));
		msgsize = msg[0] < 128 ? largemsg : smallmsg;
		corrupt = msg[1] < 25;
		memcpy(buff, msg, msgsize);
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, msgsize, sizeof(buff)));
		if (corrupt)
		{
			buff[msg[2] % sizeof(buff)] -= 1;
			EXPECT_NE(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
		}
		else
		{
			EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
			ASSERT_BUFFEREQ(msg, msgsize, payload, msgsize);
		}

		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg, sizeof(msg)));
		msgsize = msg[0] < 128 ? largemsg : smallmsg;
		corrupt = msg[1] < 25;
		memcpy(buff, msg, msgsize);
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, msgsize, sizeof(buff)));
		if (corrupt)
		{
			buff[msg[2] % sizeof(buff)] += 1;
			EXPECT_NE(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
		}
		else
		{
			EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
			ASSERT_BUFFEREQ(msg, msgsize, payload, msgsize);
		}
	}
}

TEST(Context, MultiMessagesManyInterleavedRandomSizeWithCorruption50Percent) {
	TEST_PREAMBLE_CLIENT_SERVER;

	uint8_t buff[128] = {};
	constexpr uint32_t smallmsg = sizeof(buff) - MR_OVERHEAD_WITH_ECDH;
	constexpr uint32_t largemsg = sizeof(buff) - MR_OVERHEAD_WITHOUT_ECDH;
	uint8_t msg[largemsg] = {};
	uint8_t* payload = 0;
	uint32_t payloadsize = 0;
	uint32_t msgsize = 0;
	bool corrupt = false;

	for (int i = 0; i < 50; i++)
	{
		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg, sizeof(msg)));
		msgsize = msg[0] < 128 ? largemsg : smallmsg;
		corrupt = msg[1] < 128;
		memcpy(buff, msg, msgsize);
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff, msgsize, sizeof(buff)));
		if (corrupt)
		{
			buff[msg[2] % sizeof(buff)] -= 1;
			EXPECT_NE(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
		}
		else
		{
			EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
			ASSERT_BUFFEREQ(msg, msgsize, payload, msgsize);
		}

		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg, sizeof(msg)));
		msgsize = msg[0] < 128 ? largemsg : smallmsg;
		corrupt = msg[1] < 128;
		memcpy(buff, msg, msgsize);
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff, msgsize, sizeof(buff)));
		if (corrupt)
		{
			buff[msg[2] % sizeof(buff)] += 1;
			EXPECT_NE(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
		}
		else
		{
			EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, buff, sizeof(buff), sizeof(buff), &payload, &payloadsize));
			ASSERT_BUFFEREQ(msg, msgsize, payload, msgsize);
		}
	}
}

TEST(Context, MultiMessagesManyInterleavedRandomSizeWithDelays) {
	TEST_PREAMBLE_CLIENT_SERVER;

	constexpr uint32_t buffsize = 128;
	constexpr uint32_t smallmsg = buffsize - MR_OVERHEAD_WITH_ECDH;
	constexpr uint32_t largemsg = buffsize - MR_OVERHEAD_WITHOUT_ECDH;
	uint8_t* payload = 0;
	uint32_t payloadsize = 0;
	uint32_t msgsize = 0;
	bool wait = false;
	std::queue<std::tuple<std::array<uint8_t, buffsize>, std::array<uint8_t, largemsg>, uint32_t>> servermessages;
	std::queue<std::tuple<std::array<uint8_t, buffsize>, std::array<uint8_t, largemsg>, uint32_t>> clientmessages;

	std::array<uint8_t, largemsg> msg{};
	std::array<uint8_t, buffsize> buff{};

	for (int i = 0; i < 50; i++)
	{
		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg.data(), (uint32_t)msg.size()));
		msgsize = msg[0] < 128 ? largemsg : smallmsg;
		wait = msg[1] < 128;
		memcpy(buff.data(), msg.data(), msgsize);
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff.data(), msgsize, (uint32_t)buff.size()));
		servermessages.push(std::make_tuple(buff, msg, msgsize));
		if (!wait)
		{
			while (!servermessages.empty())
			{
				auto& _buf = std::get<0>(servermessages.front());
				auto& _msg = std::get<1>(servermessages.front());
				auto& _msgsize = std::get<2>(servermessages.front());

				EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, _buf.data(), (uint32_t)_buf.size(), (uint32_t)_buf.size(), &payload, &payloadsize));
				ASSERT_BUFFEREQ(_msg.data(), _msgsize, payload, _msgsize);
				servermessages.pop();
			}
		}

		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg.data(), (uint32_t)msg.size()));
		msgsize = msg[0] < 128 ? largemsg : smallmsg;
		wait = msg[1] < 128;
		memcpy(buff.data(), msg.data(), msgsize);
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff.data(), msgsize, (uint32_t)buff.size()));
		clientmessages.push(std::make_tuple(buff, msg, msgsize));
		if (!wait)
		{
			while (!clientmessages.empty())
			{
				auto& _buf = std::get<0>(clientmessages.front());
				auto& _msg = std::get<1>(clientmessages.front());
				auto& _msgsize = std::get<2>(clientmessages.front());

				EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, _buf.data(), (uint32_t)_buf.size(), (uint32_t)_buf.size(), &payload, &payloadsize));
				ASSERT_BUFFEREQ(_msg.data(), _msgsize, payload, _msgsize);
				clientmessages.pop();
			}
		}
	}
}

TEST(Context, MultiMessagesManyInterleavedRandomSizeWithReorders) {
	TEST_PREAMBLE_CLIENT_SERVER;

	constexpr uint32_t buffsize = 128;
	constexpr uint32_t smallmsg = buffsize - MR_OVERHEAD_WITH_ECDH;
	constexpr uint32_t largemsg = buffsize - MR_OVERHEAD_WITHOUT_ECDH;
	uint8_t* payload = 0;
	uint32_t payloadsize = 0;
	uint32_t msgsize = 0;
	bool wait = false;
	std::stack<std::tuple<std::array<uint8_t, buffsize>, std::array<uint8_t, largemsg>, uint32_t>> servermessages;
	std::stack<std::tuple<std::array<uint8_t, buffsize>, std::array<uint8_t, largemsg>, uint32_t>> clientmessages;

	std::array<uint8_t, largemsg> msg{};
	std::array<uint8_t, buffsize> buff{};

	for (int i = 0; i < 50; i++)
	{
		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg.data(), (uint32_t)msg.size()));
		msgsize = msg[0] < 128 ? largemsg : smallmsg;
		wait = msg[1] < 128;
		memcpy(buff.data(), msg.data(), msgsize);
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff.data(), msgsize, (uint32_t)buff.size()));
		servermessages.push(std::make_tuple(buff, msg, msgsize));
		if (!wait)
		{
			while (!servermessages.empty())
			{
				auto& _buf = std::get<0>(servermessages.top());
				auto& _msg = std::get<1>(servermessages.top());
				auto& _msgsize = std::get<2>(servermessages.top());

				EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, _buf.data(), (uint32_t)_buf.size(), (uint32_t)_buf.size(), &payload, &payloadsize));
				ASSERT_BUFFEREQ(_msg.data(), _msgsize, payload, _msgsize);
				servermessages.pop();
			}
		}

		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg.data(), (uint32_t)msg.size()));
		msgsize = msg[0] < 128 ? largemsg : smallmsg;
		wait = msg[1] < 128;
		memcpy(buff.data(), msg.data(), msgsize);
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff.data(), msgsize, (uint32_t)buff.size()));
		clientmessages.push(std::make_tuple(buff, msg, msgsize));
		if (!wait)
		{
			while (!clientmessages.empty())
			{
				auto& _buf = std::get<0>(clientmessages.top());
				auto& _msg = std::get<1>(clientmessages.top());
				auto& _msgsize = std::get<2>(clientmessages.top());

				EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, _buf.data(), (uint32_t)_buf.size(), (uint32_t)_buf.size(), &payload, &payloadsize));
				ASSERT_BUFFEREQ(_msg.data(), _msgsize, payload, _msgsize);
				clientmessages.pop();
			}
		}
	}
}
TEST(Context, MultiMessagesManyInterleavedRandomSizeWithReordersAndDrops) {
	TEST_PREAMBLE_CLIENT_SERVER;

	constexpr uint32_t buffsize = 128;
	constexpr uint32_t smallmsg = buffsize - MR_OVERHEAD_WITH_ECDH;
	constexpr uint32_t largemsg = buffsize - MR_OVERHEAD_WITHOUT_ECDH;
	uint8_t* payload = 0;
	uint32_t payloadsize = 0;
	uint32_t msgsize = 0;
	bool wait = false;
	bool drop = false;
	std::stack<std::tuple<std::array<uint8_t, buffsize>, std::array<uint8_t, largemsg>, uint32_t>> servermessages;
	std::stack<std::tuple<std::array<uint8_t, buffsize>, std::array<uint8_t, largemsg>, uint32_t>> clientmessages;

	std::array<uint8_t, largemsg> msg{};
	std::array<uint8_t, buffsize> buff{};

	for (int i = 0; i < 100; i++)
	{
		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg.data(), (uint32_t)msg.size()));
		msgsize = msg[0] < 128 ? largemsg : smallmsg;
		wait = msg[1] < 128;
		drop = msg[5] < 128;
		memcpy(buff.data(), msg.data(), msgsize);
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(client, buff.data(), msgsize, (uint32_t)buff.size()));
		if (!drop) servermessages.push(std::make_tuple(buff, msg, msgsize));
		if (!wait)
		{
			while (!servermessages.empty())
			{
				auto& _buf = std::get<0>(servermessages.top());
				auto& _msg = std::get<1>(servermessages.top());
				auto& _msgsize = std::get<2>(servermessages.top());

				EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(server, _buf.data(), (uint32_t)_buf.size(), (uint32_t)_buf.size(), &payload, &payloadsize));
				ASSERT_BUFFEREQ(_msg.data(), _msgsize, payload, _msgsize);
				servermessages.pop();
			}
		}

		ASSERT_EQ(MR_E_SUCCESS, mr_rng_generate(rng, msg.data(), (uint32_t)msg.size()));
		msgsize = msg[0] < 128 ? largemsg : smallmsg;
		wait = msg[1] < 128;
		drop = msg[5] < 128;
		memcpy(buff.data(), msg.data(), msgsize);
		EXPECT_EQ(MR_E_SUCCESS, mr_ctx_send(server, buff.data(), msgsize, (uint32_t)buff.size()));
		if (!drop) clientmessages.push(std::make_tuple(buff, msg, msgsize));
		if (!wait)
		{
			while (!clientmessages.empty())
			{
				auto& _buf = std::get<0>(clientmessages.top());
				auto& _msg = std::get<1>(clientmessages.top());
				auto& _msgsize = std::get<2>(clientmessages.top());

				EXPECT_EQ(MR_E_SUCCESS, mr_ctx_receive(client, _buf.data(), (uint32_t)_buf.size(), (uint32_t)_buf.size(), &payload, &payloadsize));
				ASSERT_BUFFEREQ(_msg.data(), _msgsize, payload, _msgsize);
				clientmessages.pop();
			}
		}
	}
}