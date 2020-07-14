#include "pch.h"
#include "microratchet.h"
#include "internal.h"


#if defined(MR_TRACE)

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

	const char nl[2] = { '\n', 0 };
	MR_WRITE(nl, 1);
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

#define is_aligned(wut) ((((size_t)(wut)) % sizeof(size_t)) == 0)

void mr_memcpy(void* dst, const void* src, size_t amt)
{
	ptrdiff_t iamt = (ptrdiff_t)amt;
	if (is_aligned(dst) && is_aligned(src))
	{
		if (is_aligned(iamt))
		{
			for (ptrdiff_t a = 0; a < iamt / sizeof(size_t); a++)
			{
				((size_t*)dst)[a] = ((size_t*)src)[a];
			}
		}
		else
		{
			for (ptrdiff_t a = 0; a < ((ptrdiff_t)(iamt / sizeof(size_t))) - 1; a++)
			{
				((size_t*)dst)[a] = ((size_t*)src)[a];
			}
			for (ptrdiff_t i = iamt / sizeof(size_t) * sizeof(size_t); i < iamt; i++)
			{
				((uint8_t*)dst)[i] = ((uint8_t*)src)[i];
			}
		}
	}
	else
	{
		for (ptrdiff_t i = 0; i < iamt; i++)
		{
			((uint8_t*)dst)[i] = ((uint8_t*)src)[i];
		}
	}
}

void mr_memzero(void* dst, size_t amt)
{
	ptrdiff_t iamt = (ptrdiff_t)amt;
	if (!is_aligned(dst))
	{
		ptrdiff_t off = sizeof(size_t) - ((size_t)dst) % sizeof(size_t);
		for (int i = 0; i < off && i < iamt; i++)
		{
			((uint8_t*)dst)[i] = 0;
		}
		dst = (void*)((size_t)dst + off);
		iamt -= off < iamt ? off : iamt;
	}

	if (iamt > 0)
	{
		if (is_aligned(iamt))
		{
			for (ptrdiff_t a = 0; a < (ptrdiff_t)(iamt / sizeof(size_t)); a++)
			{
				((size_t*)dst)[a] = 0;
			}
		}
		else
		{
			ptrdiff_t a;
			for (a = 0; a < ((ptrdiff_t)(iamt / sizeof(size_t))) - 1; a++)
			{
				((size_t*)dst)[a] = 0;
			}
			for (ptrdiff_t i = a * sizeof(size_t); i < iamt; i++)
			{
				((uint8_t*)dst)[i] = 0;
			}
		}
	}
}