#include "pch.h"
#include "microratchet.h"
#include "internal.h"

#if defined(MR_TRACE) && defined(MR_WRITE)

#include <stdio.h>

void mr_write(const char* msg, uint32_t msglen)
{
	printf("%s\n", msg);
}

void _mrlog(const char* msg, uint32_t msglen, const uint8_t* data, uint32_t amt)
{
	MR_WRITE(msg, msglen);

	while (data && amt)
	{
		static const char lookup[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
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

	printf("\n");
}

#endif