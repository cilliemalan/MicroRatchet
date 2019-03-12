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


static std::map<void*, std::promise<int>> nexts;

static void test_next(int status, mr_ctx mr_ctx)
{
	auto i = nexts.find(mr_ctx);
	i->second.set_value(status);
}

void init_wait(mr_ctx mr_ctx)
{
	auto i = nexts.find(mr_ctx);
	if (i == nexts.end())
	{
		std::promise<int> n;
		nexts.emplace(std::make_pair(mr_ctx, std::move(n)));
	}
	else
	{
		std::promise<int> n;
		nexts[mr_ctx] = std::move(n);
	}

	_mr_ctx* ctx = reinterpret_cast<_mr_ctx*>(mr_ctx);
	ctx->next = test_next;
}

int wait_getvalue(mr_ctx mr_ctx)
{
	auto i = nexts.find(mr_ctx);
	auto f = i->second.get_future();
	f.wait();
	int result = f.get();
	nexts.erase(i);
	return result;
}

void wait_abandon(mr_ctx ctx)
{
	nexts.erase(ctx);
}