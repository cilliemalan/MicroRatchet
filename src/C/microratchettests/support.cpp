#include "pch.h"
#include <microratchet.h>
#include "support.h"
#include <internal.h>


// allocation functions for mr

int mr_allocate(mr_ctx ctx, int amountrequested, void** pointer)
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
			static_assert(sizeof(char) == 1, "char must be 1 byte");
			*pointer = new char[amountrequested];
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
		delete[] reinterpret_cast<char*>(pointer);
	}
}
