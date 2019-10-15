#include "pch.h"
#include <microratchet.h>
#include "support.h"
#include <internal.h>
#include <unordered_map>
#include <gtest/gtest.h>

// allocation functions for mr
#ifdef DEBUGMEM
static std::unordered_map<void*, size_t> memory;
static size_t allocated_memory = 0;
static size_t max_allocated_memory = 0;
#endif

mr_result_t mr_allocate(mr_ctx ctx, int amountrequested, void** pointer)
{
	if (pointer != nullptr)
	{
		if (amountrequested <= 0)
		{
			*pointer = nullptr;
			return MR_E_INVALIDSIZE;
		}
		else
		{
			static_assert(sizeof(uint8_t) == 1, "uint8_t must be 1 byte");
			*pointer = new uint8_t[amountrequested];
			if (*pointer)
			{
#ifdef DEBUGMEM
				memory[*pointer] = amountrequested;
				allocated_memory += amountrequested;
				if (allocated_memory > max_allocated_memory)
				{
					max_allocated_memory = allocated_memory;
				}
#ifdef TRACEMEM
				printf("alloc 0x%x (%d bytes, total is %d bytes)\n", reinterpret_cast<size_t>(*pointer), amountrequested, allocated_memory);
#endif
#endif

				return MR_E_SUCCESS;
			}
			else
			{
				return MR_E_NOMEM;
			}
		}
	}
	else
	{
		return MR_E_INVALIDARG;
	}
}

void mr_free(mr_ctx ctx, void* pointer)
{
	if (pointer)
	{
#ifdef DEBUGMEM
		auto szptr = memory.find(pointer);
#if defined(TRACEMEM)
		if (szptr == memory.end())
		{
			printf("ATTEMPT TO FREE UNKNOWN MEMORY at 0x%x\n", reinterpret_cast<size_t>(pointer));
		}
		else
		{
			printf("freed 0x%x (%d bytes)\n", reinterpret_cast<size_t>(pointer), szptr->second);
		}
#endif 
		ASSERT_NE(szptr, memory.end());
		if (szptr != memory.end())
		{
			allocated_memory -= szptr->second;
			memory.erase(szptr);
		}
#endif
		delete[] reinterpret_cast<uint8_t*>(pointer);
	}
}

size_t calculate_memory_used()
{
#if defined(DEBUGMEM) && defined(TRACEMEM)
	if (max_allocated_memory > 0)
	{
		printf("maximum amount allocated: %d\n", max_allocated_memory);
	}
	return allocated_memory;
#else
	return 0;
#endif
}

void free_all()
{
#ifdef DEBUGMEM
	for (auto m : memory)
	{
#ifdef TRACEMEM
		printf("unfreed memory at 0x%x (%d bytes)\n", reinterpret_cast<size_t>(m.first), m.second);
#endif
		delete[] reinterpret_cast<uint8_t*>(m.first);
	}

	max_allocated_memory = 0;
	allocated_memory = 0;
	memory.clear();
#endif
}