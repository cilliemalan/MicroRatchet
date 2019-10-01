#include "pch.h"
#include "microratchet.h"
#include "internal.h"

void _mrlog(const char* msg, const uint8_t* data, uint32_t amt)
{
	printf("%s", msg);

	while (amt > 0)
	{
		static char lookup[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
		char buf[129];
		int numcharsleft = min(sizeof(buf) / 2, amt);
		for (int i = 0; numcharsleft; i++)
		{
			buf[i] = lookup[data[i] >> 4];
			buf[i + 1] = lookup[data[i] & 0xf];
		}
		buf[numcharsleft * 2] = 0;
		printf("%s", msg);
	}

	printf("\n");
}