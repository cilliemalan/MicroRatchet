#pragma once

void init_wait(void* a, void* b, void* c);
int wait_getvalue(void* a, void* b, void* c);

template<class TCtx, class... Args>
static int call_and_wait(int(*call)(TCtx, Args...), mr_ctx ctx, TCtx _ctx, Args... args)
{
	auto a = static_cast<void*>(ctx);
	auto b = static_cast<void*>(_ctx);
	auto c = static_cast<void*>(*call);
	init_wait(a, b, c);

	int r = call(_ctx, args...);
	if (r != E_SUCCESS) return r;

	return wait_getvalue(a, b, c);
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
	ASSERT_STREQ(sbuffer1, sbuffer2); \
}