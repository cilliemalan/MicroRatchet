#pragma once


// #define DEBUGMEM
// #define TRACEMEM

#define SIZEOF(x) static_cast<uint32_t>(sizeof(x))

template<class... Args>
static int call_and_wait(int(*call)(Args...), mr_ctx ctx, Args... args)
{
	return call(args...);
}

inline void buffer_to_string(const uint8_t* b, uint32_t l, char* ob)
{
	for (uint32_t i = 0; i < l; i++)
	{
		uint8_t c = b[i];
		ob[i * 2 + 0] = "0123456789ABCDEF"[(c >> 4) & 0x0F];
		ob[i * 2 + 1] = "0123456789ABCDEF"[c & 0x0F];
	}
	ob[l * 2] = 0;
}

#define ASSERT_BUFFEREQ(b1, l1, b2, l2) { \
	uint32_t __l1 = static_cast<uint32_t>(l1); \
	uint32_t __l2 = static_cast<uint32_t>(l2); \
	const uint8_t* __b1 = static_cast<const uint8_t*>(b1); \
	const uint8_t* __b2 = static_cast<const uint8_t*>(b2); \
	ASSERT_EQ(__l1, __l2); \
	char *sbuffer1 = new char[static_cast<size_t>(__l1)*2+1]; \
	char *sbuffer2 = new char[static_cast<size_t>(__l2)*2+1]; \
	buffer_to_string(__b1, __l1, sbuffer1); \
	buffer_to_string(__b2, __l2, sbuffer2); \
	GTEST_ASSERT_(::testing::internal::CmpHelperSTREQ(#b1, #b2, sbuffer1, sbuffer2), GTEST_FATAL_FAILURE_); \
	delete[] sbuffer1; delete[] sbuffer2; \
}

#define ASSERT_BUFFERNE(b1, l1, b2, l2) { \
	uint32_t __l1 = static_cast<uint32_t>(l1); \
	uint32_t __l2 = static_cast<uint32_t>(l2); \
	const uint8_t* __b1 = static_cast<const uint8_t*>(b1); \
	const uint8_t* __b2 = static_cast<const uint8_t*>(b2); \
	ASSERT_EQ(__l1, __l2); \
	char *sbuffer1 = new char[static_cast<size_t>(__l1)*2+1]; \
	char *sbuffer2 = new char[static_cast<size_t>(__l2)*2+1]; \
	buffer_to_string(__b1, __l1, sbuffer1); \
	buffer_to_string(__b2, __l2, sbuffer2); \
	GTEST_ASSERT_(::testing::internal::CmpHelperSTRNE(#b1, #b2, sbuffer1, sbuffer2), GTEST_FATAL_FAILURE_); \
	delete[] sbuffer1; delete[] sbuffer2; \
}

#define EXPECT_BUFFEREQ(b1, l1, b2, l2) { \
	uint32_t __l1 = static_cast<uint32_t>(l1); \
	uint32_t __l2 = static_cast<uint32_t>(l2); \
	const uint8_t* __b1 = static_cast<const uint8_t*>(b1); \
	const uint8_t* __b2 = static_cast<const uint8_t*>(b2); \
	EXPECT_EQ(__l1, __l2); \
	char *sbuffer1 = new char[static_cast<size_t>(__l1)*2+1]; \
	char *sbuffer2 = new char[static_cast<size_t>(__l2)*2+1]; \
	buffer_to_string(__b1, __l1, sbuffer1); \
	buffer_to_string(__b2, __l2, sbuffer2); \
	GTEST_ASSERT_(::testing::internal::CmpHelperSTREQ(#b1, #b2, sbuffer1, sbuffer2), GTEST_NONFATAL_FAILURE_); \
	delete[] sbuffer1; delete[] sbuffer2; \
}

#define EXPECT_BUFFERNE(b1, l1, b2, l2) { \
	uint32_t __l1 = static_cast<uint32_t>(l1); \
	uint32_t __l2 = static_cast<uint32_t>(l2); \
	const uint8_t* __b1 = static_cast<const uint8_t*>(b1); \
	const uint8_t* __b2 = static_cast<const uint8_t*>(b2); \
	EXPECT_EQ(__l1, __l2); \
	char *sbuffer1 = new char[static_cast<size_t>(__l1)*2+1]; \
	char *sbuffer2 = new char[static_cast<size_t>(__l2)*2+1]; \
	buffer_to_string(__b1, __l1, sbuffer1); \
	buffer_to_string(__b2, __l2, sbuffer2); \
	GTEST_ASSERT_(::testing::internal::CmpHelperSTRNE(#b1, #b2, sbuffer1, sbuffer2), GTEST_NONFATAL_FAILURE_); \
	delete[] sbuffer1; delete[] sbuffer2; \
}

#define ASSERT_BUFFEREQS(b1, b2) ASSERT_BUFFEREQ(b1, sizeof(b1), b2, sizeof(b2))
#define ASSERT_BUFFERNES(b1, b2) ASSERT_BUFFERNE(b1, sizeof(b1), b2, sizeof(b2))
#define EXPECT_BUFFEREQS(b1, b2) ASSERT_BUFFEREQ(b1, sizeof(b1), b2, sizeof(b2))
#define EXPECT_BUFFERNES(b1, b2) ASSERT_BUFFERNE(b1, sizeof(b1), b2, sizeof(b2))

struct run_on_exit {
	inline run_on_exit(std::function<void(void)> wut) : wut(wut) {}
	inline ~run_on_exit() { wut(); }
	std::function<void(void)> wut;
};

size_t calculate_memory_used();
void free_all();

#define EXPECT_ALL_MEMORY_FREED() EXPECT_EQ((size_t)0, calculate_memory_used())










#define TEST(test_suite_name, test_name) \
inline void test_suite_name##_##test_name##_Test_internal(); \
GTEST_TEST(test_suite_name, test_name) \
{ \
	free_all(); \
	test_suite_name##_##test_name##_Test_internal(); \
	EXPECT_ALL_MEMORY_FREED(); \
	free_all(); \
} \
inline void test_suite_name##_##test_name##_Test_internal()


