#include "pch.h"
#include "microratchet.h"
#include "internal.h"

// sizes are aligned on 4 byte boundaries because
// some platforms don't allow unaligned loads (e.g. ARM).
// and so some objects have a 4 byte header containing
// bits indiciating what is present

#define STORAGE_VERSION 1


// ratchet state
#define HAS_NUM_BIT (1 << 0)
#define HAS_ECDH_BIT (1 << 1)
#define HAS_NEXTROOTKEY_BIT (1 << 2)
#define HAS_SHK_BIT (1 << 3)
#define HAS_NSHK_BIT (1 << 4)
#define HAS_RHK_BIT (1 << 5)
#define HAS_NRHK_BIT (1 << 6)
#define HAS_SCHAIN_BIT (1 << 7)
#define HAS_SCHAIN_OK_BIT (1 << 8)
#define HAS_RCHAIN_BIT (1 << 9)
#define HAS_RCHAIN_OK_BIT (1 << 10)

// main state
#define HAS_INIT_BIT (1 << 0)
#define HAS_RATCHETS_BIT (1 << 1)

// server state
#define HAS_ISERVER (1 << 2)
#define HAS_NEXT_INITIALIZATION_NONCE_BIT (1 << 3)
#define HAS_ROOTKEY_BIT (1 << 4)
#define HAS_FIRSTSENDHEADERKEY_BIT (1 << 5)
#define HAS_FIRSTRECVHEADERKEY_BIT (1 << 6)
#define HAS_LOCALSTEP0_BIT (1 << 7)
#define HAS_LOCALSTEP1_BIT (1 << 8)
#define HAS_CLIENTPUB_BIT (1 << 9)

// client state
#define HAS_CLIENT (1 << 2)
#define HAS_INITIALIZATION_NONCE_BIT (1 << 3)
#define HAS_LOCALECDH_BIT (1 << 4)


static inline bool allzeroes(const uint8_t* d, uint32_t amt)
{
	for (uint32_t i = 0; i < amt; i++)
	{
		if (d[i] != 0) return false;
	}

	return true;
}

static uint32_t init_size_needed_client(_mr_initialization_state_client* c)
{
	uint32_t size = 0;
	if (c)
	{
		if (!allzeroes(c->initializationnonce, INITIALIZATION_NONCE_SIZE))
		{
			size += INITIALIZATION_NONCE_SIZE;
		}
		if (c->localecdhforinit)
		{
			size += mr_ecdh_store_size_needed(c->localecdhforinit);
		}
	}
	return size;
}

static uint32_t init_size_needed_server(_mr_initialization_state_server* c)
{
	uint32_t size = 0;
	if (c)
	{
		if (!allzeroes(c->nextinitializationnonce, INITIALIZATION_NONCE_SIZE))
		{
			size += INITIALIZATION_NONCE_SIZE;
		}
		if (!allzeroes(c->rootkey, KEY_SIZE))
		{
			size += KEY_SIZE;
		}
		if (!allzeroes(c->firstsendheaderkey, KEY_SIZE))
		{
			size += KEY_SIZE;
		}
		if (!allzeroes(c->firstreceiveheaderkey, KEY_SIZE))
		{
			size += KEY_SIZE;
		}
		if (c->localratchetstep0)
		{
			size += mr_ecdh_store_size_needed(c->localratchetstep0);
		}
		if (c->localratchetstep1)
		{
			size += mr_ecdh_store_size_needed(c->localratchetstep1);
		}
		if (!allzeroes(c->clientpublickey, ECNUM_SIZE))
		{
			size += ECNUM_SIZE;
		}
	}
	return size;
}

static uint32_t ratchet_size_needed(_mr_ratchet_state* r)
{
	uint32_t size = 4;
	if (r->ecdhkey)
	{
		size += mr_ecdh_store_size_needed(r->ecdhkey);
	}
	if (!allzeroes(r->nextrootkey, KEY_SIZE))
	{
		size += KEY_SIZE;
	}
	if (!allzeroes(r->sendheaderkey, KEY_SIZE))
	{
		size += KEY_SIZE;
	}
	if (!allzeroes(r->nextsendheaderkey, KEY_SIZE))
	{
		size += KEY_SIZE;
	}
	if (!allzeroes(r->receiveheaderkey, KEY_SIZE))
	{
		size += KEY_SIZE;
	}
	if (!allzeroes(r->nextreceiveheaderkey, KEY_SIZE))
	{
		size += KEY_SIZE;
	}
	if (r->sendingchain.generation != 0)
	{
		size += 4;
		size += KEY_SIZE;
		if (r->sendingchain.oldgeneration != 0)
		{
			size += 4;
			size += KEY_SIZE;
		}
	}
	if (r->receivingchain.generation != 0)
	{
		size += 4;
		size += KEY_SIZE;
		if (r->receivingchain.oldgeneration != 0)
		{
			size += 4;
			size += KEY_SIZE;
		}
	}

	return size;
}

uint32_t mr_ctx_state_size_needed(mr_ctx _ctx)
{
	_mr_ctx* ctx = _ctx;

	bool initialized = ctx->init.initialized;
	bool client = ctx->config.is_client;

	uint32_t size = 4;
	if (!initialized)
	{
		if (client)
		{
			_mr_initialization_state_client* c = ctx->init.client;
			size += init_size_needed_client(c);
		}
		else
		{
			_mr_initialization_state_server* c = ctx->init.server;
			size += init_size_needed_server(c);
		}
	}

	_mr_ratchet_state* r = ctx->ratchet;
	while (r)
	{
		size += ratchet_size_needed(r);
		r = r->next;
	}

	return size;
}

#define INCPTR(amt) \
if (space < amt) return MR_E_INVALIDSIZE; \
space -= amt; \
ptr += amt;

#define WRITEDATA(data, amt) \
if (space < amt) return MR_E_INVALIDSIZE; \
mr_memcpy(ptr, data, amt); \
INCPTR(amt);

#define WRITEECDH(ecdh) { \
	uint32_t __amtneeded = mr_ecdh_store_size_needed(ecdh); \
	if (space < __amtneeded) return MR_E_INVALIDSIZE; \
	_C(mr_ecdh_store(ecdh, ptr, space)); \
	INCPTR(__amtneeded); \
}

#define WRITEUINT32(thing) \
if (space < 4) return MR_E_INVALIDSIZE; \
STATIC_ASSERT(sizeof(thing) == 4, "sizeof(thing) == 4"); \
ptr[0] = (thing) & 0xff; \
ptr[1] = ((thing) >> 8) & 0xff; \
ptr[2] = ((thing) >> 16) & 0xff; \
ptr[3] = (thing) >> 24; \
INCPTR(4);

mr_result mr_ctx_state_store(mr_ctx _ctx, uint8_t* ptr, uint32_t space)
{
	_mr_ctx* ctx = _ctx;

	bool initialized = ctx->init.initialized;
	bool client = ctx->config.is_client;

	uint32_t* mainheader = (uint32_t*)ptr;
	*mainheader = STORAGE_VERSION << 24;
	INCPTR(4);
	if (!initialized)
	{
		*mainheader |= HAS_INIT_BIT;
		if (client)
		{
			_mr_initialization_state_client* c = ctx->init.client;
			if (c)
			{
				*mainheader |= HAS_CLIENT;
				if (!allzeroes(c->initializationnonce, INITIALIZATION_NONCE_SIZE))
				{
					WRITEDATA(c->initializationnonce, INITIALIZATION_NONCE_SIZE);
					*mainheader |= HAS_INITIALIZATION_NONCE_BIT;
				}
				if (c->localecdhforinit)
				{
					WRITEECDH(c->localecdhforinit);
					*mainheader |= HAS_LOCALECDH_BIT;
				}
			}
		}
		else
		{
			_mr_initialization_state_server* c = ctx->init.server;
			if (c)
			{
				*mainheader |= HAS_ISERVER;
				if (!allzeroes(c->nextinitializationnonce, INITIALIZATION_NONCE_SIZE))
				{
					WRITEDATA(c->nextinitializationnonce, INITIALIZATION_NONCE_SIZE);
					*mainheader |= HAS_NEXT_INITIALIZATION_NONCE_BIT;
				}
				if (!allzeroes(c->rootkey, KEY_SIZE))
				{
					WRITEDATA(c->rootkey, KEY_SIZE);
					*mainheader |= HAS_ROOTKEY_BIT;
				}
				if (!allzeroes(c->firstsendheaderkey, KEY_SIZE))
				{
					WRITEDATA(c->firstsendheaderkey, KEY_SIZE);
					*mainheader |= HAS_FIRSTSENDHEADERKEY_BIT;
				}
				if (!allzeroes(c->firstreceiveheaderkey, KEY_SIZE))
				{
					WRITEDATA(c->firstreceiveheaderkey, KEY_SIZE);
					*mainheader |= HAS_FIRSTRECVHEADERKEY_BIT;
				}
				if (c->localratchetstep0)
				{
					WRITEECDH(c->localratchetstep0);
					*mainheader |= HAS_LOCALSTEP0_BIT;
				}
				if (c->localratchetstep1)
				{
					WRITEECDH(c->localratchetstep1);
					*mainheader |= HAS_LOCALSTEP1_BIT;
				}
				if (!allzeroes(c->clientpublickey, ECNUM_SIZE))
				{
					WRITEDATA(c->clientpublickey, ECNUM_SIZE);
					*mainheader |= HAS_CLIENTPUB_BIT;
				}
			}
		}
	}

	uint32_t numratchets = 0;
	_mr_ratchet_state* r = ctx->ratchet;
	while(r)
	{
		numratchets++;
		uint32_t* ratchetheader = (uint32_t*)ptr;
		*ratchetheader = 0;
		INCPTR(4);
		if (r->ecdhkey)
		{
			WRITEECDH(r->ecdhkey);
			*ratchetheader |= HAS_ECDH_BIT;
		}
		if (!allzeroes(r->nextrootkey, KEY_SIZE))
		{
			WRITEDATA(r->nextrootkey, KEY_SIZE);
			*ratchetheader |= HAS_NEXTROOTKEY_BIT;
		}
		if (!allzeroes(r->sendheaderkey, KEY_SIZE))
		{
			WRITEDATA(r->sendheaderkey, KEY_SIZE);
			*ratchetheader |= HAS_SHK_BIT;
		}
		if (!allzeroes(r->nextsendheaderkey, KEY_SIZE))
		{
			WRITEDATA(r->nextsendheaderkey, KEY_SIZE);
			*ratchetheader |= HAS_NSHK_BIT;
		}
		if (!allzeroes(r->receiveheaderkey, KEY_SIZE))
		{
			WRITEDATA(r->receiveheaderkey, KEY_SIZE);
			*ratchetheader |= HAS_RHK_BIT;
		}
		if (!allzeroes(r->nextreceiveheaderkey, KEY_SIZE))
		{
			WRITEDATA(r->nextreceiveheaderkey, KEY_SIZE);
			*ratchetheader |= HAS_NRHK_BIT;
		}
		if (!allzeroes(r->sendingchain.chainkey, KEY_SIZE))
		{
			WRITEUINT32(r->sendingchain.generation);
			WRITEDATA(r->sendingchain.chainkey, KEY_SIZE);
			*ratchetheader |= HAS_SCHAIN_BIT;
			if (r->sendingchain.oldgeneration != 0)
			{
				WRITEUINT32(r->sendingchain.oldgeneration);
				WRITEDATA(r->sendingchain.oldchainkey, KEY_SIZE);
				*ratchetheader |= HAS_SCHAIN_OK_BIT;
			}
		}
		if (!allzeroes(r->receivingchain.chainkey, KEY_SIZE))
		{
			WRITEUINT32(r->receivingchain.generation);
			WRITEDATA(r->receivingchain.chainkey, KEY_SIZE);
			*ratchetheader |= HAS_RCHAIN_BIT;
			if (r->receivingchain.oldgeneration != 0)
			{
				WRITEUINT32(r->receivingchain.oldgeneration);
				WRITEDATA(r->receivingchain.oldchainkey, KEY_SIZE);
				*ratchetheader |= HAS_RCHAIN_OK_BIT;
			}
		}

		r = r->next;
	}

	*mainheader |= numratchets << 16;

	return MR_E_SUCCESS;
}

#define READDATA(data, amt) \
if (space < amt) return MR_E_INVALIDSIZE; \
mr_memcpy(data, ptr, amt); \
INCPTR(amt);

#define READECDH(ecdh) \
	if (ecdh) mr_ecdh_destroy(ecdh); \
	ecdh = mr_ecdh_create(ctx); \
	{ \
		uint32_t __advance = mr_ecdh_load(ecdh, ptr, space); \
		if (__advance == 0) return MR_E_INVALIDOP; \
		INCPTR(__advance); \
	}

#define READUINT32(thing) \
if (space < 4) return MR_E_INVALIDSIZE; \
STATIC_ASSERT(sizeof(thing) == 4, "sizeof(thing) == 4"); \
thing = ((ptr)[3] << 24) | ((ptr)[2] << 16) | ((ptr)[1] << 8) | ((ptr)[0]); \
INCPTR(4);

mr_result mr_ctx_state_load(mr_ctx _ctx, const uint8_t* ptr, uint32_t space, uint32_t* amountread)
{
	// TODO: memory could leak if an allocation fails
	_mr_ctx* ctx = _ctx;

	uint32_t ospace = space;
	bool client = ctx->config.is_client;
	uint32_t mainheader;
	READUINT32(mainheader);
	if (mainheader & HAS_INIT_BIT)
	{
		ctx->init.initialized = false;
		if (client)
		{
			if (mainheader & HAS_CLIENT)
			{
				if (!ctx->init.client)
				{
					_C(mr_allocate(ctx, sizeof(_mr_initialization_state_client), (void**)&ctx->init.client));
				}
				else
				{
					if (ctx->init.client->localecdhforinit)
					{
						mr_ecdh_destroy(ctx->init.client->localecdhforinit);
					}
				}

				_mr_initialization_state_client* c = ctx->init.client;

				mr_memzero(c, sizeof(_mr_initialization_state_client));

				if (mainheader & HAS_INITIALIZATION_NONCE_BIT)
				{
					READDATA(c->initializationnonce, INITIALIZATION_NONCE_SIZE);
				}
				if (mainheader & HAS_LOCALECDH_BIT)
				{
					READECDH(c->localecdhforinit);
				}
			}
			else
			{
				if (ctx->init.client)
				{
					mr_free(ctx, ctx->init.client);
					ctx->init.client = 0;
				}
			}
		}
		else
		{
			if (mainheader & HAS_ISERVER)
			{
				if (!ctx->init.server)
				{
					_C(mr_allocate(ctx, sizeof(_mr_initialization_state_server), (void**)&ctx->init.server));
					mr_memzero(ctx->init.server, sizeof(_mr_initialization_state_server));
				}
				else
				{
					if (ctx->init.server->localratchetstep0)
					{
						mr_ecdh_destroy(ctx->init.server->localratchetstep0);
					}
					if (ctx->init.server->localratchetstep1)
					{
						mr_ecdh_destroy(ctx->init.server->localratchetstep1);
					}
				}

				_mr_initialization_state_server* c = ctx->init.server;

				mr_memzero(c, sizeof(_mr_initialization_state_server));

				if (mainheader & HAS_NEXT_INITIALIZATION_NONCE_BIT)
				{
					READDATA(c->nextinitializationnonce, INITIALIZATION_NONCE_SIZE);
				}
				if (mainheader & HAS_ROOTKEY_BIT)
				{
					READDATA(c->rootkey, KEY_SIZE);
				}
				if (mainheader & HAS_FIRSTSENDHEADERKEY_BIT)
				{
					READDATA(c->firstsendheaderkey, KEY_SIZE);
				}
				if (mainheader & HAS_FIRSTRECVHEADERKEY_BIT)
				{
					READDATA(c->firstreceiveheaderkey, KEY_SIZE);
				}
				if (mainheader & HAS_LOCALSTEP0_BIT)
				{
					READECDH(c->localratchetstep0);
				}
				if (mainheader & HAS_LOCALSTEP1_BIT)
				{
					READECDH(c->localratchetstep1);
				}
				if (mainheader & HAS_CLIENTPUB_BIT)
				{
					READDATA(c->clientpublickey, ECNUM_SIZE);
				}
			}
			else
			{
				if (ctx->init.server)
				{
					mr_free(ctx, ctx->init.server);
					ctx->init.server = 0;
				}
			}
		}
	}
	else
	{
		ctx->init.initialized = true;
	}

	// make sure all previous ratchets are destroyed
	ratchet_destroy_all(ctx);

	// load ratchets
	uint32_t numRatchets = (mainheader >> 16) & 0xff;
	_mr_ratchet_state* first = 0;
	_mr_ratchet_state* prev = 0;
	for (uint32_t i = 0; i < numRatchets; i++)
	{
		_mr_ratchet_state* r;
		_C(mr_allocate(ctx, sizeof(_mr_ratchet_state), (void**)&r));
		mr_memzero(r, sizeof(_mr_ratchet_state));

		if (i == 0)
		{
			ctx->ratchet = r;
			prev = r;
		}
		else
		{
			prev->next = r;
			prev = r;
		}

		uint32_t ratchetheader;
		READUINT32(ratchetheader);

		if (ratchetheader & HAS_ECDH_BIT)
		{
			READECDH(r->ecdhkey);
		}
		if (ratchetheader & HAS_NEXTROOTKEY_BIT)
		{
			READDATA(r->nextrootkey, KEY_SIZE);
		}
		if (ratchetheader & HAS_SHK_BIT)
		{
			READDATA(r->sendheaderkey, KEY_SIZE);
		}
		if (ratchetheader & HAS_NSHK_BIT)
		{
			READDATA(r->nextsendheaderkey, KEY_SIZE);
		}
		if (ratchetheader & HAS_RHK_BIT)
		{
			READDATA(r->receiveheaderkey, KEY_SIZE);
		}
		if (ratchetheader & HAS_NRHK_BIT)
		{
			READDATA(r->nextreceiveheaderkey, KEY_SIZE);
		}
		if (ratchetheader & HAS_SCHAIN_BIT)
		{
			READUINT32(r->sendingchain.generation);
			READDATA(r->sendingchain.chainkey, KEY_SIZE);
			if (ratchetheader & HAS_SCHAIN_OK_BIT)
			{
				READUINT32(r->sendingchain.oldgeneration);
				READDATA(r->sendingchain.oldchainkey, KEY_SIZE);
			}
		}
		if (ratchetheader & HAS_RCHAIN_BIT)
		{
			READUINT32(r->receivingchain.generation);
			READDATA(r->receivingchain.chainkey, KEY_SIZE);
			if (ratchetheader & HAS_RCHAIN_OK_BIT)
			{
				READUINT32(r->receivingchain.oldgeneration);
				READDATA(r->receivingchain.oldchainkey, KEY_SIZE);
			}
		}
	}

	if (amountread) *amountread = ospace - space;
	return MR_E_SUCCESS;
}




