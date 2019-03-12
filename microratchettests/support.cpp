#include "pch.h"
#include <microratchet.h>
#include "support.h"


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



static std::map<std::tuple<void*, void*, void*>, std::promise<int>> promises;

void init_wait(void* a, void* b, void* c)
{
	std::tuple<void*, void*, void*> k{ a,b,c };
	auto i = promises.find(k);
	if (i == promises.end())
	{
		std::promise<int> n;
		promises.emplace(std::make_pair(k, std::move(n)));
	}
	else
	{
		std::promise<int> n;
		promises[k] = std::move(n);
	}
}

template<class TCtx, class TFnc>
static void wait_setvalue(mr_ctx mr_ctx, TCtx ctx, TFnc call, int status)
{
	void* a = static_cast<void*>(mr_ctx);
	void* b = static_cast<void*>(ctx);
	void* c = static_cast<void*>(call);

	wait_setvalue(a, b, c, status);
}

static void wait_setvalue(void* a, void* b, void* c, int value)
{
	std::tuple<void*, void*, void*> k{ a,b,c };
	auto i = promises.find(k);
	i->second.set_value(value);
}

int wait_getvalue(void* a, void* b, void* c)
{
	std::tuple<void*, void*, void*> k{ a,b,c };
	auto i = promises.find(k);
	auto f = i->second.get_future();
	f.wait();
	int result = f.get();
	promises.erase(i);
	return result;
}



#define REGISTER_CB(cs, fn) void mr_##cs##_##fn##_cb(int status, mr_##cs##_ctx ctx, mr_ctx mr_ctx) { wait_setvalue(mr_ctx, ctx, mr_##cs##_##fn, status); }

REGISTER_CB(sha, init)
REGISTER_CB(sha, compute)
REGISTER_CB(sha, process)
