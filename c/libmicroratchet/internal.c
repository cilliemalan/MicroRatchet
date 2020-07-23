#include "pch.h"
#include "microratchet.h"
#include "internal.h"

#ifndef MR_WRITE
#define MR_WRITE(...)
#endif

#if MR_DEBUG ||  MR_TRACE
static const char lookup[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

static void writehex(const uint8_t* data, size_t amt)
{
	while (data && amt)
	{
		char buf[17];
		size_t numcharsleft = (sizeof(buf) / 2) < amt ? (sizeof(buf) / 2) : amt;
		for (size_t i = 0; i < numcharsleft; i++)
		{
			buf[i * 2] = lookup[data[i] >> 4];
			buf[i * 2 + 1] = lookup[data[i] & 0xf];
		}
		buf[numcharsleft * 2] = 0;
		MR_WRITE(buf, (uint32_t)(numcharsleft * 2));
		data += numcharsleft;
		amt -= numcharsleft;
	}

}

void _mrlogctxid(mr_ctx ctx)
{
	writehex(((uint8_t*)&ctx), 4);
}
#endif


#if MR_TRACE_DATA
void _mrloghex(const uint8_t* data, uint32_t amt)
{
	writehex(data, amt);
}
#endif

void mr_memcpy(void* dst, const void* src, size_t amt)
{
	memcpy(dst, src, amt);
}

void mr_memzero(void* dst, size_t amt)
{
	memset(dst, 0, amt);
}

#ifdef MR_WRITE_PRINTF
void MR_WRITE(const char* msg, size_t amt)
{
	// msg will always be null terminated
	printf("%s", msg);
}
#endif