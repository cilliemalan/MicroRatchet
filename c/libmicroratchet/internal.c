#include "pch.h"
#include "microratchet.h"
#include "internal.h"

#if defined(DEBUG)

#include <stdio.h>

void _mrlog(const char* msg, const uint8_t* data, uint32_t amt)
{
	printf("%s", msg);

	while (data && amt > 0)
	{
		static char lookup[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
		char buf[65];
		int numcharsleft = (sizeof(buf) / 2) < amt ? (sizeof(buf) / 2) : amt;
		for (int i = 0; i < numcharsleft; i++)
		{
			buf[i * 2] = lookup[data[i] >> 4];
			buf[i * 2 + 1] = lookup[data[i] & 0xf];
		}
		buf[numcharsleft * 2] = 0;
		printf("%s", buf);
		data += numcharsleft;
		amt -= numcharsleft;
	}

	printf("\n");
}

#endif