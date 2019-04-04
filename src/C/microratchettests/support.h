#pragma once

template<class... Args>
static int call_and_wait(int(*call)(Args...), mr_ctx ctx, Args... args)
{
	return call(args...);
}

inline void buffer_to_string(const unsigned char* b1, unsigned int l1, char* outputbuffer)
{
	for (unsigned int i = 0; i < l1; i++)
	{
		unsigned char c = b1[i];
		outputbuffer[i * 2 + 0] = "0123456789ABCDEF"[c >> 4];
		outputbuffer[i * 2 + 1] = "0123456789ABCDEF"[c & 0x0F];
	}
	outputbuffer[l1 * 2] = 0;
}

#define ASSERT_BUFFEREQ(b1, l1, b2, l2) { \
	unsigned int __l1 = static_cast<unsigned int>(l1); \
	unsigned int __l2 = static_cast<unsigned int>(l2); \
	const unsigned char* __b1 = static_cast<const unsigned char*>(b1); \
	const unsigned char* __b2 = static_cast<const unsigned char*>(b2); \
	ASSERT_EQ(__l1, __l2); \
	char *sbuffer1 = new char[l1*2+1]; \
	char *sbuffer2 = new char[l1*2+1]; \
	buffer_to_string(__b1, __l1, sbuffer1); \
	buffer_to_string(__b2, __l2, sbuffer2); \
	GTEST_ASSERT_(::testing::internal::CmpHelperSTREQ(#b1, #b2, sbuffer1, sbuffer2), GTEST_FATAL_FAILURE_); \
	delete[] sbuffer1; delete[] sbuffer2; \
}

#define ASSERT_BUFFERNE(b1, l1, b2, l2) { \
	unsigned int __l1 = static_cast<unsigned int>(l1); \
	unsigned int __l2 = static_cast<unsigned int>(l2); \
	const unsigned char* __b1 = static_cast<const unsigned char*>(b1); \
	const unsigned char* __b2 = static_cast<const unsigned char*>(b2); \
	ASSERT_EQ(__l1, __l2); \
	char *sbuffer1 = new char[l1*2+1]; \
	char *sbuffer2 = new char[l1*2+1]; \
	buffer_to_string(__b1, __l1, sbuffer1); \
	buffer_to_string(__b2, __l2, sbuffer2); \
	GTEST_ASSERT_(::testing::internal::CmpHelperSTRNE(#b1, #b2, sbuffer1, sbuffer2), GTEST_FATAL_FAILURE_); \
	delete[] sbuffer1; delete[] sbuffer2; \
}


#define EXPECT_BUFFEREQ(b1, l1, b2, l2) { \
	unsigned int __l1 = static_cast<unsigned int>(l1); \
	unsigned int __l2 = static_cast<unsigned int>(l2); \
	const unsigned char* __b1 = static_cast<const unsigned char*>(b1); \
	const unsigned char* __b2 = static_cast<const unsigned char*>(b2); \
	EXPECT_EQ(__l1, __l2); \
	char *sbuffer1 = new char[l1*2+1]; \
	char *sbuffer2 = new char[l1*2+1]; \
	buffer_to_string(__b1, __l1, sbuffer1); \
	buffer_to_string(__b2, __l2, sbuffer2); \
	GTEST_ASSERT_(::testing::internal::CmpHelperSTREQ(#b1, #b2, sbuffer1, sbuffer2), GTEST_NONFATAL_FAILURE_); \
	delete[] sbuffer1; delete[] sbuffer2; \
}

#define EXPECT_BUFFERNE(b1, l1, b2, l2) { \
	unsigned int __l1 = static_cast<unsigned int>(l1); \
	unsigned int __l2 = static_cast<unsigned int>(l2); \
	const unsigned char* __b1 = static_cast<const unsigned char*>(b1); \
	const unsigned char* __b2 = static_cast<const unsigned char*>(b2); \
	EXPECT_EQ(__l1, __l2); \
	char *sbuffer1 = new char[l1*2+1]; \
	char *sbuffer2 = new char[l1*2+1]; \
	buffer_to_string(__b1, __l1, sbuffer1); \
	buffer_to_string(__b2, __l2, sbuffer2); \
	GTEST_ASSERT_(::testing::internal::CmpHelperSTRNE(#b1, #b2, sbuffer1, sbuffer2), GTEST_NONFATAL_FAILURE_); \
	delete[] sbuffer1; delete[] sbuffer2; \
}
