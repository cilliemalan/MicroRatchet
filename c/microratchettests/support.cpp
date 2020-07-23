#include "pch.h"
#include <microratchet.h>
#include "support.h"
#include <internal.h>
#include <unordered_map>
#include <gtest/gtest.h>
#include <inttypes.h>
#include <atomic>

// allocation functions for mr
#if defined (DEBUGMEM) || defined(TRACEMEM)
struct allocation_info
{
	size_t size;
	size_t num;
};

static std::unordered_map<void*, allocation_info> memory;
static size_t allocated_memory = 0;
static size_t max_allocated_memory = 0;
static std::atomic<size_t> allocation_num = 0;
#endif

mr_result mr_allocate(mr_ctx ctx, int amountrequested, void** pointer)
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
#if defined (DEBUGMEM) || defined(TRACEMEM)
				++allocation_num;
				memory[*pointer] = { (size_t)amountrequested, allocation_num.load() };
				allocated_memory += amountrequested;
				if (allocated_memory > max_allocated_memory)
				{
					max_allocated_memory = allocated_memory;
				}
#if defined(TRACEMEM)
				auto n = allocation_num.load();
				printf("+++ 0x%" PRIxPTR " [%8" PRId32 "] -> [%8" PRIdPTR "]  #%" PRIdPTR "\n", reinterpret_cast<size_t>(*pointer), amountrequested, allocated_memory, n);
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
#if defined (DEBUGMEM) || defined(TRACEMEM)

		auto szptr = memory.find(pointer);

		bool valid = szptr != memory.end();
		auto allocinfo = szptr->second;
		if (valid)
		{
			allocated_memory -= allocinfo.size;
			memory.erase(szptr);
		}

#if defined (DEBUGMEM)
		ASSERT_TRUE(valid);
#endif

#if defined(TRACEMEM)
		if (!valid)
		{
			printf("ATTEMPT TO FREE UNKNOWN MEMORY at 0x%" PRIxPTR "\n", reinterpret_cast<size_t>(pointer));
		}
		else
		{
			printf("--- 0x%" PRIxPTR " [%8" PRIdPTR "] -> [%8" PRIdPTR "] (#%" PRIdPTR ")\n", reinterpret_cast<size_t>(pointer), allocinfo.size, allocated_memory, allocinfo.num);
		}
#endif 

#endif


		delete[] reinterpret_cast<uint8_t*>(pointer);
	}
	else
	{
		printf("ATTEMPT TO FREE NULL POINTER\n");
	}
}

size_t calculate_memory_used()
{
#if defined(DEBUGMEM) && defined(TRACEMEM)
	if (max_allocated_memory > 0)
	{
		printf("maximum amount allocated: %" PRIdPTR "\n", max_allocated_memory);
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
		printf("unfreed memory at 0x%" PRIxPTR " (%" PRIdPTR " bytes #%" PRIdPTR ")\n", reinterpret_cast<size_t>(m.first), m.second.size, m.second.num);
#endif

		// delete[] reinterpret_cast<uint8_t*>(m.first);
	}

	max_allocated_memory = 0;
	allocated_memory = 0;
	memory.clear();
#endif
}