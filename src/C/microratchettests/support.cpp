#include "pch.h"
#include <microratchet.h>
#include "support.h"
#include <internal.h>
#include <unordered_map>
#include <gtest/gtest.h>

// allocation functions for mr
static std::unordered_map<void*, size_t> memory;

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
			memory[*pointer] = amountrequested;
#ifdef TRACE
			printf("alloc 0x%x (%d bytes)\n", reinterpret_cast<size_t>(*pointer), amountrequested);
#endif
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
		auto szptr = memory.find(pointer);
#if defined(TRACE)
		if (szptr == memory.end())
		{
			printf("ATTEMPT TO FREE UNKNOWN MEMORY at 0x%x\n", reinterpret_cast<size_t>(pointer));
		}
		else
		{
			printf("freed 0x%x (%d bytes)\n", reinterpret_cast<size_t>(pointer), szptr->second);
		}
		ASSERT_NE(szptr, memory.end());
#endif 
		if (szptr != memory.end()) memory.erase(szptr);
		delete[] reinterpret_cast<uint8_t*>(pointer);
	}
}

size_t calculate_memory_used()
{
	size_t sum = 0;
	for (const auto &p : memory) sum += p.second;
	return sum;
}

void free_all()
{
	for (auto m : memory)
	{
#ifdef TRACE
		printf("unfreed memory at 0x%x (%d bytes)\n", reinterpret_cast<size_t>(m.first), m.second);
#endif
		delete[] reinterpret_cast<uint8_t*>(m.first);
	}

	memory.clear();
}