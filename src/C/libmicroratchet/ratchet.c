#include "pch.h"
#include "microratchet.h"
#include "internal.h"

int ratchet_getorder(mr_ctx mr_ctx, int* indexes, unsigned int numindexes)
{
	if (!mr_ctx || !indexes) return E_INVALIDOP;
	if (numindexes < NUM_RATCHETS) return E_INVALIDSIZE;
	_mr_ctx* ctx = (_mr_ctx*)mr_ctx;

	unsigned int mustbeunder = 0xffffffff;
	for (int i = 0; i < NUM_RATCHETS; i++)
	{
		// find the biggest one
		unsigned int maxnum = 0;
		int index = -1;
		if (mustbeunder > 0)
		{
			for (int j = 0; j < NUM_RATCHETS; j++)
			{
				if (ctx->ratchets[i].num > maxnum && ctx->ratchets[i].num < mustbeunder)
				{
					maxnum = ctx->ratchets[i].num;
					index = i;
				}
			}
		}

		indexes[i] = index;
		mustbeunder = maxnum;
	}

	return E_SUCCESS;
}

int ratchet_getoldest(mr_ctx mr_ctx, _mr_ratchet_state** ratchet)
{
	if (!mr_ctx || !ratchet) return E_INVALIDOP;
	_mr_ctx * ctx = (_mr_ctx*)mr_ctx;

	unsigned int minnum = 0xffffffff;
	int minix = -1;
	for (int i = 0; i < NUM_RATCHETS; i++)
	{
		if (ctx->ratchets[i].num == 0)
		{
			minix = i;
			break;
		}
		else if (ctx->ratchets[i].num < minnum)
		{
			minnum = ctx->ratchets[i].num;
			minix = i;
		}
	}

	if (minix < 0) return E_NOTFOUND;
	*ratchet = &ctx->ratchets[minix];
	return E_SUCCESS;
}

int ratchet_getsecondtolast(mr_ctx mr_ctx, _mr_ratchet_state** ratchet)
{
	if (!mr_ctx || !ratchet) return E_INVALIDOP;
	_mr_ctx * ctx = (_mr_ctx*)mr_ctx;

	unsigned int maxnum = 0;
	int maxix = -1;
	int notmaxix = -1;
	for (int i = 0; i < NUM_RATCHETS; i++)
	{
		if (ctx->ratchets[i].num > maxnum)
		{
			maxnum = ctx->ratchets[i].num;
			notmaxix = maxix;
			maxix = i;
		}
	}

	if (notmaxix < 0) return E_NOTFOUND;
	*ratchet = &ctx->ratchets[notmaxix];
	return E_SUCCESS;
}

int ratchet_getlast(mr_ctx mr_ctx, _mr_ratchet_state** ratchet)
{
	if (!mr_ctx || !ratchet) return E_INVALIDOP;
	_mr_ctx * ctx = (_mr_ctx*)mr_ctx;

	unsigned int maxnum = 0;
	int maxix = -1;
	for (int i = 0; i < NUM_RATCHETS; i++)
	{
		if (ctx->ratchets[i].num > maxnum)
		{
			maxnum = ctx->ratchets[i].num;
			maxix = i;
		}
	}

	if (maxix < 0) return E_NOTFOUND;
	*ratchet = &ctx->ratchets[maxix];
	return E_SUCCESS;
}

int ratchet_initialize_server(mr_ctx mr_ctx,
	_mr_ratchet_state* ratchet,
	mr_ecdh_ctx previouskeypair,
	unsigned char* rootkey, unsigned int rootkeysize,
	unsigned char* remotepubickey, unsigned int remotepubickeysize,
	mr_ecdh_ctx keypair,
	unsigned char* receiveheaderkey, unsigned int receiveheaderkeysize,
	unsigned char* sendheaderkey, unsigned int sendheaderkeysize)
{
	if (!mr_ctx || !ratchet || !previouskeypair || !keypair) return E_INVALIDARGUMENT;
	if (!rootkey || !remotepubickey) return E_INVALIDARGUMENT;
	if (rootkeysize != KEY_SIZE || remotepubickeysize != KEY_SIZE) return E_INVALIDSIZE;
	if (receiveheaderkey && receiveheaderkeysize != KEY_SIZE) return E_INVALIDSIZE;
	if (sendheaderkey && sendheaderkeysize != KEY_SIZE) return E_INVALIDSIZE;

	memset(ratchet, 0, sizeof(_mr_ratchet_state));
	ratchet->ecdhkey = keypair;
	ratchet->num = 1;

	unsigned char tmp[KEY_SIZE * 3];

	// receiving chain
	_C(mr_ecdh_derivekey(previouskeypair, remotepubickey, remotepubickeysize, tmp, KEY_SIZE));
	_C(kdf_compute(mr_ctx, tmp, sizeof(tmp), rootkey, rootkeysize, tmp, sizeof(tmp)));
	_C(chain_initialize(mr_ctx, &ratchet->receivingchain, receiveheaderkey, receiveheaderkeysize, tmp + KEY_SIZE, KEY_SIZE, tmp + KEY_SIZE * 2, KEY_SIZE));
	rootkey = tmp;

	// sending chain
	_C(mr_ecdh_derivekey(keypair, remotepubickey, remotepubickeysize, tmp, KEY_SIZE));
	_C(kdf_compute(mr_ctx, tmp, sizeof(tmp), rootkey, rootkeysize, tmp, sizeof(tmp)));
	_C(chain_initialize(mr_ctx, &ratchet->sendingchain, sendheaderkey, sendheaderkeysize, tmp + KEY_SIZE, KEY_SIZE, tmp + KEY_SIZE * 2, KEY_SIZE));
	rootkey = tmp;

	memcpy(ratchet->nextrootkey, rootkey, KEY_SIZE);

	return E_SUCCESS;
}

int ratchet_initialize_client(mr_ctx mr_ctx,
	_mr_ratchet_state * ratchet1,
	_mr_ratchet_state * ratchet2,
	unsigned char* rootkey, unsigned int rootkeysize,
	unsigned char* remotepubickey0, unsigned int remotepubickey0size,
	unsigned char* remotepubickey1, unsigned int remotepubickey1size,
	mr_ecdh_ctx keypair,
	unsigned char* receiveheaderkey, unsigned int receiveheaderkeysize,
	unsigned char* sendheaderkey, unsigned int sendheaderkeysize,
	mr_ecdh_ctx nextkeypair)
{
	if (!mr_ctx || !ratchet1 || !ratchet2 || !nextkeypair || !keypair) return E_INVALIDARGUMENT;
	if (!rootkey || !remotepubickey0 || !remotepubickey1) return E_INVALIDARGUMENT;
	if (!receiveheaderkey || !sendheaderkey) return E_INVALIDARGUMENT;
	if (rootkeysize != KEY_SIZE || remotepubickey0size != KEY_SIZE || remotepubickey1size != KEY_SIZE) return E_INVALIDSIZE;
	if (receiveheaderkeysize != KEY_SIZE || sendheaderkeysize != KEY_SIZE) return E_INVALIDSIZE;

	memset(ratchet1, 0, sizeof(_mr_ratchet_state));
	memset(ratchet2, 0, sizeof(_mr_ratchet_state));
	ratchet1->ecdhkey = keypair;
	ratchet1->num = 1;

	unsigned char tmp[KEY_SIZE * 3];

	// sending chain
	_C(mr_ecdh_derivekey(keypair, remotepubickey0, remotepubickey0size, tmp, KEY_SIZE));
	_C(kdf_compute(mr_ctx, tmp, sizeof(tmp), rootkey, rootkeysize, tmp, sizeof(tmp)));
	_C(chain_initialize(mr_ctx, &ratchet1->sendingchain, sendheaderkey, sendheaderkeysize, tmp + KEY_SIZE, KEY_SIZE, tmp + KEY_SIZE * 2, KEY_SIZE));
	rootkey = tmp;

	memcpy(tmp, ratchet1->sendingchain.nextheaderkey, KEY_SIZE);
	memset(ratchet1->sendingchain.nextheaderkey, 0, KEY_SIZE);

	_C(ratchet_initialize_server(mr_ctx,
		ratchet1,
		keypair,
		rootkey, rootkeysize,
		remotepubickey1, remotepubickey1size,
		nextkeypair,
		receiveheaderkey, receiveheaderkeysize,
		tmp, KEY_SIZE));
	ratchet1->num = 2;

	return E_SUCCESS;
}

int ratchet_initialize(
	mr_ctx mr_ctx,
	_mr_ratchet_state * ratchet,
	unsigned int num,
	mr_ecdh_ctx ecdhkey,
	unsigned char* nextrootkey, unsigned int nextrootkeysize,
	unsigned int receivinggeneration,
	unsigned char* receivingheaderkey, unsigned int receivingheaderkeysize,
	unsigned char* receivingnextheaderkey, unsigned int receivingnextheaderkeysize,
	unsigned char* receivingchainkey, unsigned int receivingchainkeysize,
	unsigned int sendinggeneration,
	unsigned char* sendingheaderkey, unsigned int sendingheaderkeysize,
	unsigned char* sendingnextheaderkey, unsigned int sendingnextheaderkeysize,
	unsigned char* sendingchainkey, unsigned int sendingchainkeysize)
{
	if (!ratchet || !mr_ctx) return E_INVALIDARGUMENT;
	if (nextrootkey && nextrootkeysize != KEY_SIZE) return E_INVALIDSIZE;
	if (receivingheaderkey && receivingheaderkeysize != KEY_SIZE) return E_INVALIDSIZE;
	if (receivingnextheaderkey && receivingnextheaderkeysize != KEY_SIZE) return E_INVALIDSIZE;
	if (receivingchainkey && receivingchainkeysize != KEY_SIZE) return E_INVALIDSIZE;
	if (sendingheaderkey && sendingheaderkeysize != KEY_SIZE) return E_INVALIDSIZE;
	if (sendingnextheaderkey && sendingnextheaderkeysize != KEY_SIZE) return E_INVALIDSIZE;
	if (sendingchainkey && sendingchainkeysize != KEY_SIZE) return E_INVALIDSIZE;

	ratchet->num = num;
	ratchet->ecdhkey = ecdhkey;
	if (nextrootkey) memcpy(ratchet->nextrootkey, nextrootkey, KEY_SIZE);
	else memset(ratchet->nextrootkey, 0, KEY_SIZE);
	_C(chain_initialize(mr_ctx, &ratchet->receivingchain,
		receivingheaderkey, receivingheaderkeysize,
		receivingchainkey, receivingchainkeysize,
		receivingnextheaderkey, receivingnextheaderkeysize));
	ratchet->receivingchain.generation = receivinggeneration;
	_C(chain_initialize(mr_ctx, &ratchet->sendingchain,
		sendingheaderkey, sendingheaderkeysize,
		sendingchainkey, sendingchainkeysize,
		sendingnextheaderkey, sendingnextheaderkeysize));

	return E_SUCCESS;
}

int ratchet_ratchet(mr_ctx mr_ctx, _mr_ratchet_state * ratchet, _mr_ratchet_state * nextratchet, unsigned char* remotepublickey, unsigned int remotepublickeysize, mr_ecdh_ctx keypair)
{
	if (!ratchet || !nextratchet || !remotepublickey || !keypair) return E_INVALIDARGUMENT;
	if (remotepublickeysize != KEY_SIZE) return E_INVALIDSIZE;

	_C(ratchet_initialize_server(mr_ctx, nextratchet,
		ratchet->ecdhkey,
		ratchet->nextrootkey, KEY_SIZE,
		remotepublickey, remotepublickeysize,
		keypair,
		ratchet->receivingchain.nextheaderkey, KEY_SIZE,
		ratchet->sendingchain.nextheaderkey, KEY_SIZE));

	nextratchet->num = ratchet->num + 1;
	ratchet->ecdhkey = 0;
	memset(ratchet->nextrootkey, 0, KEY_SIZE);
	memset(ratchet->receivingchain.nextheaderkey, 0, KEY_SIZE);
	memset(ratchet->sendingchain.nextheaderkey, 0, KEY_SIZE);

	return E_SUCCESS;
}

int chain_initialize(mr_ctx mr_ctx, _mr_chain_state * chain_state, const unsigned char* headerkey, unsigned int headerkeysize, const unsigned char* chainkey, unsigned int chainkeysize, const unsigned char* nextheaderkey, unsigned int nextheaderkeysize)
{
	if (!chain_state) return E_INVALIDARGUMENT;
	if (headerkey && headerkeysize != KEY_SIZE) return E_INVALIDSIZE;
	if (chainkey && chainkeysize != KEY_SIZE) return E_INVALIDSIZE;
	if (nextheaderkey && nextheaderkeysize != KEY_SIZE) return E_INVALIDSIZE;

	if (headerkey) memcpy(chain_state->headerkey, headerkey, 32);
	else memset(chain_state->headerkey, 0, 32);
	if (chainkey) memcpy(chain_state->chainkey, chainkey, 32);
	else memset(chain_state->chainkey, 0, 32);
	if (nextheaderkey) memcpy(chain_state->nextheaderkey, nextheaderkey, 32);
	else memset(chain_state->nextheaderkey, 0, 32);
	chain_state->generation = 0;

	return E_SUCCESS;
}

int chain_ratchetforsending(mr_ctx mr_ctx, _mr_ratchet_state * ratchet, unsigned char* key, unsigned int keysize, int* generation)
{
	if (!mr_ctx || !ratchet || !key || !generation) return E_INVALIDARGUMENT;
	if (keysize != MSG_KEY_SIZE) return E_INVALIDSIZE;

	unsigned char tmp[KEY_SIZE + MSG_KEY_SIZE];

	unsigned char* chain = ratchet->sendingchain.chainkey;
	_C(kdf_compute(mr_ctx, chain, KEY_SIZE, 0, 0, tmp, sizeof(tmp)));

	memcpy(chain, tmp, KEY_SIZE);
	memcpy(key, tmp + KEY_SIZE, MSG_KEY_SIZE);
	*generation = ++ratchet->sendingchain.generation;

	return E_SUCCESS;
}

int chain_ratchetforreceiving(mr_ctx mr_ctx, _mr_ratchet_state * ratchet, unsigned int generation, unsigned char* key, unsigned int keysize)
{
	if (!mr_ctx || !ratchet || !key) return E_INVALIDARGUMENT;
	if (keysize != MSG_KEY_SIZE) return E_INVALIDSIZE;

	// look for a lost key
	_mr_ctx * ctx = (_mr_ctx*)mr_ctx;
	for (int i = 0; i < NUM_LOST_KEYS; i++)
	{
		if (ctx->lost_keys[i].ratchet == ratchet->num)
		{
			if (ctx->lost_keys[i].generation == generation)
			{
				memcpy(key, ctx->lost_keys[i].key, MSG_KEY_SIZE);
				memset(&ctx->lost_keys[i], 0, sizeof(_mr_lostkey));
				return E_SUCCESS;
			}
		}
	}

	if (generation <= ratchet->receivingchain.generation) return E_KEYLOST;

	unsigned char tmp[KEY_SIZE + MSG_KEY_SIZE];
	unsigned char* chain = ratchet->receivingchain.chainkey;
	unsigned char* chaintmp = chain;

	while (ratchet->receivingchain.generation < generation)
	{
		_C(kdf_compute(mr_ctx, chaintmp, KEY_SIZE, 0, 0, tmp, sizeof(tmp)));
		chaintmp = tmp;
		ratchet->receivingchain.generation++;

		// store lost key
		if (ratchet->receivingchain.generation != generation && generation - ratchet->receivingchain.generation < (NUM_LOST_KEYS / 2))
		{
			int oldest_lost_key_gen = 0x7fffffff;
			int oldest_lost_key = -1;
			for (int i = 0; i < NUM_LOST_KEYS; i++)
			{
				if (ctx->lost_keys[i].generation == 0 && ctx->lost_keys[i].ratchet == 0)
				{
					oldest_lost_key = i; break;
				}
				else
				{
					int genind = ctx->lost_keys[i].ratchet * 1000 + ctx->lost_keys[i].generation;
					if (genind < oldest_lost_key_gen)
					{
						oldest_lost_key_gen = genind;
						oldest_lost_key = i;
					}
				}
			}
		}
		else
		{
			memcpy(chain, tmp, KEY_SIZE);
			memcpy(key, tmp + KEY_SIZE, MSG_KEY_SIZE);
			return E_SUCCESS;
		}
	}

	return E_INVALIDOP;
}