#include "pch.h"
#include "microratchet.h"
#include "internal.h"

#if MR_DEBUG ||  MR_TRACE
static const char lookup[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

static void writehex(const uint8_t* data, uint32_t amt)
{
	while (data && amt)
	{
		char buf[17];
		int numcharsleft = (sizeof(buf) / 2) < amt ? (sizeof(buf) / 2) : amt;
		for (int i = 0; i < numcharsleft; i++)
		{
			buf[i * 2] = lookup[data[i] >> 4];
			buf[i * 2 + 1] = lookup[data[i] & 0xf];
		}
		buf[numcharsleft * 2] = 0;
		MR_WRITE(msg, numcharsleft * 2);
		data += numcharsleft;
		amt -= numcharsleft;
	}

}


#endif

#if MR_DEBUG

void _mrlogctxid(mr_ctx ctx)
{
	writehex(((uint8_t*)&ctx) + sizeof(size_t) - 4, 4);
}

#endif


#if MR_TRACE

void _mrlog(const char* msg, uint32_t msglen, const uint8_t* data, uint32_t amt)
{
	MR_WRITE(msg, msglen);
	writehex(data, amt);
	MR_WRITE1("\n");
}

#endif

size_t _mr_nonatomic_compare_exchange(volatile size_t* a, size_t b, size_t c)
{
	size_t r = *a;
	if (r == c) {
		*a = b;
	}

	return r;
}

void mr_memcpy(void* dst, const void* src, size_t amt)
{
	memcpy(dst, src, amt);
}

void mr_memzero(void* dst, size_t amt)
{
	memset(dst, 0, amt);
}