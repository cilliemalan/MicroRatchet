#include "pch.h"
#include "internal.h"
#include "support.h"

#include <mutex>
#include <queue>
#include <functional>
#include <thread>
#include <chrono>
using namespace std::chrono_literals;

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

struct buffer
{
	buffer(const uint8_t* data, uint32_t length)
		:length(length)
	{
		this->data = new uint8_t[length];
		memcpy(this->data, data, length);
	}

	buffer(const buffer&) = delete;

	buffer(buffer&& o)
		:data(o.data), length(o.length)
	{
		o.data = nullptr;
		o.length = 0;
	}

	~buffer()
	{
		if (data)
		{
			delete[] data;
			data = 0;
		}
	}

	uint8_t* data;
	uint32_t length;
};

struct notifier
{
	std::condition_variable cv;
	std::mutex mutex;
	bool notified = false;

	notifier() {}

	bool wait(uint32_t timeout)
	{
		std::unique_lock<std::mutex> lk(mutex);
		auto result = cv.wait_for(
			lk,
			std::chrono::milliseconds(timeout),
			[this]() { return notified; });
		notified = false;

		return result;
	}

	void notify()
	{
		{
			std::unique_lock<std::mutex> lk(mutex);
			notified = true;
		}
		cv.notify_one();
	}
};

class HighLevel
{
public:
	HighLevel(mr_ctx ctx, uint32_t data_flight_time = 0)
		:ctx(ctx), data_flight_time(data_flight_time)
	{
	}

private:
	void* create_wait_handle()
	{
		auto mtx = new notifier();
		return mtx;
	}

	void destroy_wait_handle(void* wh)
	{
		auto mtx = reinterpret_cast<notifier*>(wh);
		delete mtx;
	}

	bool wait(void* wh, uint32_t timeout)
	{
		auto mtx = reinterpret_cast<notifier*>(wh);
		return mtx->wait(timeout);
	}

	void notify(void* wh)
	{
		auto mtx = reinterpret_cast<notifier*>(wh);
		mtx->notify();
	}

	uint32_t transmit(const uint8_t* data, uint32_t amount)
	{
		if (other)
		{
			TRACEMSGCTX(ctx, "++++transmit");
			uint8_t* newdata = new uint8_t[amount];
			memcpy(newdata, data, amount);
			std::thread tmp([=]()
				{
					std::this_thread::sleep_for(std::chrono::milliseconds(data_flight_time));
					{
						std::lock_guard<std::mutex> mtx(other->mutex);
						other->queue.emplace(newdata, amount);
						TRACEMSGCTX(other->ctx, "++++receive");
					}
					mr_hl_receive(other->ctx, amount, 5000);
					delete[] newdata;
				});
			tmp.detach();
			return amount;
		}
		else
		{
			return 0;
		}
	}

	uint32_t receive(uint8_t* data, uint32_t amount)
	{
		if (other)
		{
			std::lock_guard<std::mutex> mtx(mutex);
			buffer buff = std::move(queue.front());
			queue.pop();
			if (buff.length <= amount)
			{
				memcpy(data, buff.data, buff.length);
			}
			return buff.length;
		}
		else
		{
			return 0;
		}
	}

	void data_callback(const uint8_t* data, uint32_t amount)
	{
		if (_data_callback_function)
		{
			_data_callback_function(data, amount);
		}
	}

	bool checkkey_callback(const uint8_t* pubkey, uint32_t len)
	{
		if (_checkkey_callback_function)
		{
			return _checkkey_callback_function(pubkey, len);
		}
		else
		{
			return true;
		}
	}

public:
	inline void data_callback_function(std::function<void(const uint8_t* data, uint32_t amount)> fn)
	{
		_data_callback_function = fn;
	}

	inline void checkkey_callback_function(std::function<bool(const uint8_t* pub, uint32_t len)> fn)
	{
		_checkkey_callback_function = fn;
	}

	mr_hl_config config(uint32_t message_quantization = 32, uint32_t ecdh_frequency = 4)
	{
		mr_hl_config cfg;

		cfg.user = this;

		cfg.create_wait_handle = HighLevel::_create_wait_handle;
		cfg.destroy_wait_handle = HighLevel::_destroy_wait_handle;
		cfg.wait = HighLevel::_wait;
		cfg.notify = HighLevel::_notify;
		cfg.transmit = HighLevel::_transmit;
		cfg.receive = HighLevel::_receive;
		cfg.data_callback = HighLevel::_data_callback;
		cfg.checkkey_callback = HighLevel::_checkkey_callback;

		cfg.message_quantization = message_quantization;
		cfg.ecdh_frequency = ecdh_frequency;

		return cfg;
	}

public:
	void run()
	{
		thread = std::thread([=]()
			{
				auto cfg = this->config();
				mr_hl_mainloop(ctx, &cfg);
			});
		_sleep(1);
	}

	void wait()
	{
		if (thread.joinable())
		{
			thread.join();
		}
	}

public:
	static void connect(HighLevel& a, HighLevel& b)
	{
		a.other = &b;
		b.other = &a;
	}

private:
	static void* _create_wait_handle(void* user) { return ((HighLevel*)user)->create_wait_handle(); }
	static void _destroy_wait_handle(void* user, void* wh) { ((HighLevel*)user)->destroy_wait_handle(wh); }
	static bool _wait(void* user, void* wh, uint32_t timeout) { return ((HighLevel*)user)->wait(wh, timeout); }
	static void _notify(void* user, void* wh) { ((HighLevel*)user)->notify(wh); }
	static uint32_t _transmit(void* user, const uint8_t* data, uint32_t amount) { return ((HighLevel*)user)->transmit(data, amount); }
	static uint32_t _receive(void* user, uint8_t* data, uint32_t amount) { return ((HighLevel*)user)->receive(data, amount); }
	static void _data_callback(void* user, const uint8_t* data, uint32_t amount) { ((HighLevel*)user)->data_callback(data, amount); }
	static bool _checkkey_callback(void* user, const uint8_t* pubkey, uint32_t len) { return ((HighLevel*)user)->checkkey_callback(pubkey, len); }

private:
	HighLevel(const HighLevel&) = delete;
	HighLevel(const HighLevel&&) = delete;

private:
	std::mutex mutex;
	HighLevel* other;
	std::queue<buffer> queue;
	std::thread thread;
	mr_ctx ctx;
	uint32_t data_flight_time;

	std::function<void(const uint8_t* data, uint32_t amount)> _data_callback_function;
	std::function<bool(const uint8_t* pub, uint32_t len)> _checkkey_callback_function;
};



TEST(HighLevel, Initialization)
{
	TEST_PREAMBLE;

	HighLevel a(client);
	HighLevel b(server);
	HighLevel::connect(a, b);
	a.run();
	b.run();

	mr_hl_initialize(client, 1000000);

	bool server_initialized, client_initialized;
	mr_ctx_is_initialized(client, &client_initialized);
	mr_ctx_is_initialized(server, &server_initialized);
	ASSERT_TRUE(client_initialized);
	ASSERT_TRUE(server_initialized);

	std::this_thread::sleep_for(100ms);
	mr_hl_deactivate(client, 1000);
	mr_hl_deactivate(server, 1000);
	a.wait();
	b.wait();
}

TEST(HighLevel, InitializationSlow)
{
	TEST_PREAMBLE;

	HighLevel a(client, 150);
	HighLevel b(server, 250);
	HighLevel::connect(a, b);
	a.run();
	b.run();

	mr_hl_initialize(client, 1000000);

	bool server_initialized, client_initialized;
	mr_ctx_is_initialized(client, &client_initialized);
	mr_ctx_is_initialized(server, &server_initialized);
	ASSERT_TRUE(client_initialized);
	ASSERT_TRUE(server_initialized);

	std::this_thread::sleep_for(100ms);
	mr_hl_deactivate(client, 1000);
	mr_hl_deactivate(server, 1000);
	a.wait();
	b.wait();
}

TEST(HighLevel, SendReceive)
{
	TEST_PREAMBLE;

	HighLevel a(client);
	HighLevel b(server);
	HighLevel::connect(a, b);
	a.run();
	b.run();

	mr_hl_initialize(client, 1000000);

	bool server_initialized, client_initialized;
	mr_ctx_is_initialized(client, &client_initialized);
	mr_ctx_is_initialized(server, &server_initialized);
	EXPECT_TRUE(client_initialized);
	EXPECT_TRUE(server_initialized);

	static constexpr size_t msgsize = 32;
	uint8_t message1[msgsize];
	uint8_t message2[msgsize];
	auto rng = mr_rng_create(client);
	mr_rng_generate(rng, message1, sizeof(message1));
	mr_rng_generate(rng, message2, sizeof(message2));
	mr_rng_destroy(rng);

	bool message1_received = false;
	bool message2_received = false;
	a.data_callback_function([&](auto d, auto a)
		{
			EXPECT_GE(a, msgsize);
			EXPECT_BUFFEREQ(d, msgsize, message1, msgsize);
			message1_received = true;
		});
	b.data_callback_function([&](auto d, auto a)
		{
			EXPECT_GE(a, msgsize);
			EXPECT_BUFFEREQ(d, msgsize, message2, msgsize);
			message2_received = true;
		});

	mr_hl_send(client, message2, sizeof(message2), 1000);
	mr_hl_send(server, message1, sizeof(message1), 1000);

	std::this_thread::sleep_for(100ms);
	EXPECT_TRUE(message1_received);
	EXPECT_TRUE(message2_received);

	std::this_thread::sleep_for(100ms);
	mr_hl_deactivate(client, 1000);
	mr_hl_deactivate(server, 1000);
	a.wait();
	b.wait();
}

TEST(HighLevel, SendReceive2)
{
	TEST_PREAMBLE;

	HighLevel a(client);
	HighLevel b(server);
	HighLevel::connect(a, b);
	a.run();
	b.run();

	mr_hl_initialize(client, 1000000);

	bool server_initialized, client_initialized;
	mr_ctx_is_initialized(client, &client_initialized);
	mr_ctx_is_initialized(server, &server_initialized);
	EXPECT_TRUE(client_initialized);
	EXPECT_TRUE(server_initialized);

	static constexpr size_t msgsize = 32;
	uint8_t message1[msgsize];
	uint8_t message2[msgsize];
	auto rng = mr_rng_create(client);
	mr_rng_generate(rng, message1, sizeof(message1));
	mr_rng_generate(rng, message2, sizeof(message2));
	mr_rng_destroy(rng);

	bool message1_received = false;
	bool message2_received = false;
	a.data_callback_function([&](auto d, auto a)
		{
			EXPECT_GE(a, msgsize);
			EXPECT_BUFFEREQ(d, msgsize, message1, msgsize);
			message1_received = true;
		});
	b.data_callback_function([&](auto d, auto a)
		{
			EXPECT_GE(a, msgsize);
			EXPECT_BUFFEREQ(d, msgsize, message2, msgsize);
			message2_received = true;
		});

	mr_hl_send(server, message1, sizeof(message1), 1000);
	mr_hl_send(client, message2, sizeof(message2), 1000);

	std::this_thread::sleep_for(100ms);
	EXPECT_TRUE(message1_received);
	EXPECT_TRUE(message2_received);

	std::this_thread::sleep_for(100ms);
	mr_hl_deactivate(client, 1000);
	mr_hl_deactivate(server, 1000);
	a.wait();
	b.wait();
}

TEST(HighLevel, SendReceiveSlow)
{
	TEST_PREAMBLE;

	HighLevel a(client, 222);
	HighLevel b(server, 111);
	HighLevel::connect(a, b);
	a.run();
	b.run();

	mr_hl_initialize(client, 1000000);

	bool server_initialized, client_initialized;
	mr_ctx_is_initialized(client, &client_initialized);
	mr_ctx_is_initialized(server, &server_initialized);
	EXPECT_TRUE(client_initialized);
	EXPECT_TRUE(server_initialized);

	static constexpr size_t msgsize = 32;
	uint8_t message1[msgsize];
	uint8_t message2[msgsize];
	auto rng = mr_rng_create(client);
	mr_rng_generate(rng, message1, sizeof(message1));
	mr_rng_generate(rng, message2, sizeof(message2));
	mr_rng_destroy(rng);

	bool message1_received = false;
	bool message2_received = false;
	a.data_callback_function([&](auto d, auto a)
		{
			EXPECT_GE(a, msgsize);
			EXPECT_BUFFEREQ(d, msgsize, message1, msgsize);
			message1_received = true;
		});
	b.data_callback_function([&](auto d, auto a)
		{
			EXPECT_GE(a, msgsize);
			EXPECT_BUFFEREQ(d, msgsize, message2, msgsize);
			message2_received = true;
		});

	mr_hl_send(client, message2, sizeof(message2), 1000);
	mr_hl_send(server, message1, sizeof(message1), 1000);

	std::this_thread::sleep_for(250ms);
	EXPECT_TRUE(message1_received);
	EXPECT_TRUE(message2_received);

	std::this_thread::sleep_for(300ms);
	mr_hl_deactivate(client, 1000);
	mr_hl_deactivate(server, 1000);
	a.wait();
	b.wait();
}