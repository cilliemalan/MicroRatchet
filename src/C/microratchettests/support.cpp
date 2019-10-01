#include "pch.h"
#include <microratchet.h>
#include "support.h"
#include <internal.h>

// allocation functions for mr

mr_result_t mr_allocate(mr_ctx ctx, int amountrequested, void** pointer)
{
	if (pointer != nullptr)
	{
		if (amountrequested <= 0)
		{
			*pointer = nullptr;
			return E_INVALIDSIZE;
		}
		else
		{
			static_assert(sizeof(uint8_t) == 1, "uint8_t must be 1 byte");
			*pointer = new uint8_t[amountrequested];
			if (*pointer) return E_SUCCESS;
			else return E_NOMEM;
		}
	}
	else
	{
		return E_INVALIDARGUMENT;
	}
}

void mr_free(mr_ctx ctx, void* pointer)
{
	if (pointer)
	{
		delete[] reinterpret_cast<uint8_t*>(pointer);
	}
}
