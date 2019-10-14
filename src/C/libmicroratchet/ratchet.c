#include "pch.h"
#include "microratchet.h"
#include "internal.h"

static uint8_t _chain_context[] = { 0x7d, 0x93, 0x96, 0x05, 0xf5, 0xb6, 0xd2, 0xe2, 0x65, 0xd0, 0xde, 0xe6, 0xe4, 0x5d, 0x7a, 0x2c };

static int keyallzeroes(const uint8_t* k)
{
	const uint32_t* ik = (const uint32_t* )k;
	for (int i = 0; i < KEY_SIZE / (sizeof(int) / sizeof(char)); i++)
	{
		if (ik[i] != 0) return 0;
	}
	return 1;
}

mr_result_t ratchet_getorder(mr_ctx mr_ctx, int* indexes, uint32_t numindexes)
{
	FAILIF(!mr_ctx || !indexes, E_INVALIDOP, "!mr_ctx || !indexes")
	FAILIF(numindexes < NUM_RATCHETS, E_INVALIDSIZE, "numindexes < NUM_RATCHETS")
	_mr_ctx * ctx = (_mr_ctx*)mr_ctx;

	uint32_t mustbeunder = 0xffffffff;
	for (int i = 0; i < NUM_RATCHETS; i++)
	{
		// find the biggest one
		uint32_t maxnum = 0;
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

mr_result_t ratchet_getoldest(mr_ctx mr_ctx, _mr_ratchet_state * *ratchet)
{
	FAILIF(!mr_ctx || !ratchet, E_INVALIDOP, "!mr_ctx || !ratchet")
	_mr_ctx * ctx = (_mr_ctx*)mr_ctx;

	uint32_t minnum = 0xffffffff;
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

	FAILIF(minix < 0, E_NOTFOUND, "minix < 0")
	*ratchet = &ctx->ratchets[minix];
	return E_SUCCESS;
}

mr_result_t ratchet_getsecondtolast(mr_ctx mr_ctx, _mr_ratchet_state * *ratchet)
{
	FAILIF(!mr_ctx || !ratchet, E_INVALIDOP, "!mr_ctx || !ratchet")
	_mr_ctx * ctx = (_mr_ctx*)mr_ctx;

	uint32_t maxnum = 0;
	uint32_t nextmaxnum = 0;
	int nextmaxix = -1;
	for (int i = 0; i < NUM_RATCHETS; i++)
	{
		if (ctx->ratchets[i].num > maxnum)
		{
			maxnum = ctx->ratchets[i].num;
		}
	}
	for (int i = 0; i < NUM_RATCHETS; i++)
	{
		if (ctx->ratchets[i].num < maxnum && ctx->ratchets[i].num > nextmaxnum)
		{
			nextmaxnum = ctx->ratchets[i].num;
			nextmaxix = i;
		}
	}

	FAILIF(nextmaxix < 0, E_NOTFOUND, "nextmaxix < 0")
	*ratchet = &ctx->ratchets[nextmaxix];
	return E_SUCCESS;
}

mr_result_t ratchet_getlast(mr_ctx mr_ctx, _mr_ratchet_state * *ratchet)
{
	FAILIF(!mr_ctx || !ratchet, E_INVALIDOP, "!mr_ctx || !ratchet")
	_mr_ctx * ctx = (_mr_ctx*)mr_ctx;

	uint32_t maxnum = 0;
	int maxix = -1;
	for (int i = 0; i < NUM_RATCHETS; i++)
	{
		if (ctx->ratchets[i].num > maxnum)
		{
			maxnum = ctx->ratchets[i].num;
			maxix = i;
		}
	}

	FAILIF(maxix < 0, E_NOTFOUND, "maxix < 0")
	*ratchet = &ctx->ratchets[maxix];
	return E_SUCCESS;
}

mr_result_t ratchet_add(mr_ctx mr_ctx, _mr_ratchet_state* ratchet)
{
	FAILIF(!mr_ctx || !ratchet, E_INVALIDOP, "!mr_ctx || !ratchet")
	_mr_ctx* ctx = (_mr_ctx*)mr_ctx;

	uint32_t maxnum = 0;
	uint32_t minnum = 0xffffffff;
	int minix = -1;
	for (int i = 0; i < NUM_RATCHETS; i++)
	{
		if (ctx->ratchets[i].num > maxnum)
		{
			maxnum = ctx->ratchets[i].num;
		}
		if (ctx->ratchets[i].num < minnum)
		{
			minnum = ctx->ratchets[i].num;
			minix = i;
		}
	}

	FAILIF(minix < 0, E_NOTFOUND, "minix < 0")
	if (ctx->ratchets[minix].ecdhkey) mr_ecdh_destroy(ctx->ratchets[minix].ecdhkey);
	ratchet->num = maxnum + 1;
	ctx->ratchets[minix] = *ratchet;
	return E_SUCCESS;
}

bool ratchet_destroy(_mr_ctx* ctx, int num)
{
	if (!ctx) return false;

	for (int i = 0; i < NUM_RATCHETS; i++)
	{
		if (ctx->ratchets[i].num == num)
		{
			mr_ecdh_destroy(ctx->ratchets[i].ecdhkey);
			ctx->ratchets[i] = (_mr_ratchet_state){ 0 };
			return true;
		}
	}

	return false;
}

mr_result_t ratchet_initialize_server(mr_ctx mr_ctx,
	_mr_ratchet_state * ratchet,
	mr_ecdh_ctx previouskeypair,
	const uint8_t* rootkey, uint32_t rootkeysize,
	const uint8_t* remotepubickey, uint32_t remotepubickeysize,
	mr_ecdh_ctx keypair,
	const uint8_t* receiveheaderkey, uint32_t receiveheaderkeysize,
	const uint8_t* sendheaderkey, uint32_t sendheaderkeysize)
{
	FAILIF(!mr_ctx || !ratchet || !previouskeypair || !keypair, E_INVALIDARGUMENT, "!mr_ctx || !ratchet || !previouskeypair || !keypair")
	FAILIF(previouskeypair == keypair, E_INVALIDARGUMENT, "previouskeypair == keypair")
	FAILIF(!rootkey || !remotepubickey, E_INVALIDARGUMENT, "!rootkey || !remotepubickey")
	FAILIF(rootkeysize != KEY_SIZE || remotepubickeysize != KEY_SIZE, E_INVALIDSIZE, "rootkeysize != KEY_SIZE || remotepubickeysize != KEY_SIZE")
	FAILIF(receiveheaderkey && receiveheaderkeysize != KEY_SIZE, E_INVALIDSIZE, "receiveheaderkey && receiveheaderkeysize != KEY_SIZE")
	FAILIF(sendheaderkey && sendheaderkeysize != KEY_SIZE, E_INVALIDSIZE, "sendheaderkey && sendheaderkeysize != KEY_SIZE")
	_mr_ctx* ctx = (_mr_ctx*)mr_ctx;

	LOG("--Initialize ECDH Ratchet");
	LOGD("Root Key:           ", rootkey, KEY_SIZE);
	LOGD("Receive Header Key: ", receiveheaderkey, KEY_SIZE);
	LOGD("Send Header Key:    ", sendheaderkey, KEY_SIZE);
	LOGD("ECDH Public:        ", remotepubickey, KEY_SIZE);

	memset(ratchet, 0, sizeof(_mr_ratchet_state));
	ratchet->ecdhkey = keypair; // note: pointer aliased here
	ratchet->num = 1;
	if (receiveheaderkey) memcpy(ratchet->receiveheaderkey, receiveheaderkey, KEY_SIZE);
	else memset(ratchet->receiveheaderkey, 0, KEY_SIZE);
	if (sendheaderkey) memcpy(ratchet->sendheaderkey, sendheaderkey, KEY_SIZE);
	else memset(ratchet->sendheaderkey, 0, KEY_SIZE);

	uint8_t tmp[KEY_SIZE * 3];
	uint8_t tmp_root[KEY_SIZE];

	// receiving chain
	LOG("--Receiving Chain");
	_C(mr_ecdh_derivekey(previouskeypair, remotepubickey, remotepubickeysize, tmp, KEY_SIZE));
	_C(mr_sha_init(ctx->sha_ctx));
	_C(mr_sha_process(ctx->sha_ctx, tmp, KEY_SIZE));
	_C(mr_sha_compute(ctx->sha_ctx, tmp, sizeof(tmp)));
	LOGD("  C Input Key:      ", rootkey, KEY_SIZE);
	LOGD("  C Key Info:       ", tmp, KEY_SIZE);
	_C(kdf_compute(mr_ctx, tmp, KEY_SIZE, rootkey, KEY_SIZE, tmp, sizeof(tmp)));
	LOGD("  C Key Out 0 rk:   ", tmp, KEY_SIZE);
	LOGD("  C Key Out 1 rck:  ", tmp + KEY_SIZE, KEY_SIZE);
	LOGD("  C Key Out 2 nrhk: ", tmp + KEY_SIZE * 2, KEY_SIZE);
	memcpy(tmp_root, tmp, KEY_SIZE);
	_C(chain_initialize(mr_ctx, &ratchet->receivingchain, tmp + KEY_SIZE, KEY_SIZE));
	memcpy(ratchet->nextreceiveheaderkey, tmp + KEY_SIZE * 2, KEY_SIZE);

	// sending chain
	LOG("--Sending Chain");
	_C(mr_ecdh_derivekey(keypair, remotepubickey, remotepubickeysize, tmp, KEY_SIZE));
	_C(mr_sha_init(ctx->sha_ctx));
	_C(mr_sha_process(ctx->sha_ctx, tmp, KEY_SIZE));
	_C(mr_sha_compute(ctx->sha_ctx, tmp, sizeof(tmp)));
	LOGD("  C Input Key:      ", tmp_root, KEY_SIZE);
	LOGD("  C Key Info:       ", tmp, KEY_SIZE);
	_C(kdf_compute(mr_ctx, tmp, KEY_SIZE, tmp_root, KEY_SIZE, tmp, sizeof(tmp)));
	LOGD("  C Key Out 0 nrk:  ", tmp, KEY_SIZE);
	LOGD("  C Key Out 1 sck:  ", tmp + KEY_SIZE, KEY_SIZE);
	LOGD("  C Key Out 2 nshk: ", tmp + KEY_SIZE * 2, KEY_SIZE);
	rootkey = tmp;
	_C(chain_initialize(mr_ctx, &ratchet->sendingchain, tmp + KEY_SIZE, KEY_SIZE));
	memcpy(ratchet->nextsendheaderkey, tmp + KEY_SIZE * 2, KEY_SIZE);

	// next root key
	memcpy(ratchet->nextrootkey, rootkey, KEY_SIZE);

	return E_SUCCESS;
}

mr_result_t ratchet_initialize_client(mr_ctx mr_ctx,
	_mr_ratchet_state * ratchet1,
	_mr_ratchet_state * ratchet2,
	const uint8_t* rootkey, uint32_t rootkeysize,
	const uint8_t* remotepubickey0, uint32_t remotepubickey0size,
	const uint8_t* remotepubickey1, uint32_t remotepubickey1size,
	mr_ecdh_ctx keypair,
	const uint8_t* receiveheaderkey, uint32_t receiveheaderkeysize,
	const uint8_t* sendheaderkey, uint32_t sendheaderkeysize,
	mr_ecdh_ctx nextkeypair)
{
	FAILIF(!mr_ctx || !ratchet1 || !ratchet2 || !nextkeypair || !keypair, E_INVALIDARGUMENT, "!mr_ctx || !ratchet1 || !ratchet2 || !nextkeypair || !keypair")
	FAILIF(!rootkey || !remotepubickey0 || !remotepubickey1, E_INVALIDARGUMENT, "!rootkey || !remotepubickey0 || !remotepubickey1")
	FAILIF(!receiveheaderkey || !sendheaderkey, E_INVALIDARGUMENT, "!receiveheaderkey || !sendheaderkey")
	FAILIF(rootkeysize != KEY_SIZE || remotepubickey0size != KEY_SIZE || remotepubickey1size != KEY_SIZE, E_INVALIDSIZE, "rootkeysize != KEY_SIZE || remotepubickey0size != KEY_SIZE || remotepubickey1size != KEY_SIZE")
	FAILIF(receiveheaderkeysize != KEY_SIZE || sendheaderkeysize != KEY_SIZE, E_INVALIDSIZE, "receiveheaderkeysize != KEY_SIZE || sendheaderkeysize != KEY_SIZE")
	_mr_ctx* ctx = (_mr_ctx*)mr_ctx;

	LOG("--Initialize ECDH Ratchet CLIENT");
	LOGD("Root Key:           ", rootkey, KEY_SIZE);
	LOGD("Receive Header Key: ", receiveheaderkey, KEY_SIZE);
	LOGD("Send Header Key:    ", sendheaderkey, KEY_SIZE);
	LOGD("ECDH Public 0:      ", remotepubickey0, KEY_SIZE);
	LOGD("ECDH Public 1:      ", remotepubickey1, KEY_SIZE);

	memset(ratchet1, 0, sizeof(_mr_ratchet_state));
	memset(ratchet2, 0, sizeof(_mr_ratchet_state));
	ratchet1->ecdhkey = keypair;
	ratchet1->num = 1;
	memcpy(ratchet1->sendheaderkey, sendheaderkey, KEY_SIZE);

	uint8_t tmp[KEY_SIZE * 3];

	// no receiving chain
	LOG("--NO Receiving Chain");

	// sending chain
	LOG("--Sending Chain");
	_C(mr_ecdh_derivekey(keypair, remotepubickey0, remotepubickey0size, tmp, KEY_SIZE));
	_C(mr_sha_init(ctx->sha_ctx));
	_C(mr_sha_process(ctx->sha_ctx, tmp, KEY_SIZE));
	_C(mr_sha_compute(ctx->sha_ctx, tmp, sizeof(tmp)));
	LOGD("  C Input Key:      ", rootkey, KEY_SIZE);
	LOGD("  C Key Info:       ", tmp, KEY_SIZE);
	_C(kdf_compute(mr_ctx, tmp, KEY_SIZE, rootkey, KEY_SIZE, tmp, sizeof(tmp)));
	LOGD("  C Key Out 0 nrk:  ", tmp, KEY_SIZE);
	LOGD("  C Key Out 1 sck:  ", tmp + KEY_SIZE, KEY_SIZE);
	LOGD("  C Key Out 2 nshk: ", tmp + KEY_SIZE * 2, KEY_SIZE);
	rootkey = tmp;
	_C(chain_initialize(mr_ctx, &ratchet1->sendingchain, tmp + KEY_SIZE, KEY_SIZE));

	_C(ratchet_initialize_server(mr_ctx,
		ratchet2,
		keypair,
		rootkey, KEY_SIZE,
		remotepubickey1, KEY_SIZE,
		nextkeypair,
		receiveheaderkey, KEY_SIZE,
		tmp + KEY_SIZE * 2, KEY_SIZE));

	return E_SUCCESS;
}

mr_result_t ratchet_initialize(
	mr_ctx mr_ctx,
	_mr_ratchet_state * ratchet,
	uint32_t num,
	mr_ecdh_ctx ecdhkey,
	const uint8_t* nextrootkey, uint32_t nextrootkeysize,
	uint32_t receivinggeneration,
	const uint8_t* receivingheaderkey, uint32_t receivingheaderkeysize,
	const uint8_t* receivingnextheaderkey, uint32_t receivingnextheaderkeysize,
	const uint8_t* receivingchainkey, uint32_t receivingchainkeysize,
	uint32_t sendinggeneration,
	const uint8_t* sendingheaderkey, uint32_t sendingheaderkeysize,
	const uint8_t* sendingnextheaderkey, uint32_t sendingnextheaderkeysize,
	const uint8_t* sendingchainkey, uint32_t sendingchainkeysize)
{
	FAILIF(!ratchet || !mr_ctx, E_INVALIDARGUMENT, "!ratchet || !mr_ctx")
	FAILIF(nextrootkey && nextrootkeysize != KEY_SIZE, E_INVALIDSIZE, "nextrootkey && nextrootkeysize != KEY_SIZE")
	FAILIF(receivingheaderkey && receivingheaderkeysize != KEY_SIZE, E_INVALIDSIZE, "receivingheaderkey && receivingheaderkeysize != KEY_SIZE")
	FAILIF(receivingnextheaderkey && receivingnextheaderkeysize != KEY_SIZE, E_INVALIDSIZE, "receivingnextheaderkey && receivingnextheaderkeysize != KEY_SIZE")
	FAILIF(receivingchainkey && receivingchainkeysize != KEY_SIZE, E_INVALIDSIZE, "receivingchainkey && receivingchainkeysize != KEY_SIZE")
	FAILIF(sendingheaderkey && sendingheaderkeysize != KEY_SIZE, E_INVALIDSIZE, "sendingheaderkey && sendingheaderkeysize != KEY_SIZE")
	FAILIF(sendingnextheaderkey && sendingnextheaderkeysize != KEY_SIZE, E_INVALIDSIZE, "sendingnextheaderkey && sendingnextheaderkeysize != KEY_SIZE")
	FAILIF(sendingchainkey && sendingchainkeysize != KEY_SIZE, E_INVALIDSIZE, "sendingchainkey && sendingchainkeysize != KEY_SIZE")

	ratchet->num = num;
	ratchet->ecdhkey = ecdhkey;
	if (nextrootkey) memcpy(ratchet->nextrootkey, nextrootkey, KEY_SIZE);
	else memset(ratchet->nextrootkey, 0, KEY_SIZE);
	if (receivingheaderkey) memcpy(ratchet->receiveheaderkey, receivingheaderkey, KEY_SIZE);
	else memset(ratchet->receiveheaderkey, 0, KEY_SIZE);
	if (receivingnextheaderkey) memcpy(ratchet->nextreceiveheaderkey, receivingnextheaderkey, KEY_SIZE);
	else memset(ratchet->receiveheaderkey, 0, KEY_SIZE);
	if (sendingheaderkey) memcpy(ratchet->sendheaderkey, sendingheaderkey, KEY_SIZE);
	else memset(ratchet->receiveheaderkey, 0, KEY_SIZE);
	if (sendingnextheaderkey) memcpy(ratchet->nextsendheaderkey, sendingnextheaderkey, KEY_SIZE);
	else memset(ratchet->receiveheaderkey, 0, KEY_SIZE);

	_C(chain_initialize(mr_ctx, &ratchet->receivingchain, receivingchainkey, receivingchainkeysize));
	ratchet->receivingchain.generation = receivinggeneration;
	_C(chain_initialize(mr_ctx, &ratchet->sendingchain, sendingchainkey, sendingchainkeysize));

	return E_SUCCESS;
}

mr_result_t ratchet_ratchet(mr_ctx mr_ctx, _mr_ratchet_state * ratchet, _mr_ratchet_state * nextratchet, const uint8_t* remotepublickey, uint32_t remotepublickeysize, mr_ecdh_ctx keypair)
{
	FAILIF(!ratchet || !nextratchet || !remotepublickey || !keypair, E_INVALIDARGUMENT, "!ratchet || !nextratchet || !remotepublickey || !keypair")
	FAILIF(keypair == ratchet->ecdhkey, E_INVALIDARGUMENT, "keypair == ratchet->ecdhkey")
	FAILIF(remotepublickeysize != KEY_SIZE, E_INVALIDSIZE, "remotepublickeysize != KEY_SIZE")

	_C(ratchet_initialize_server(mr_ctx, nextratchet,
		ratchet->ecdhkey,
		ratchet->nextrootkey, KEY_SIZE,
		remotepublickey, remotepublickeysize,
		keypair,
		ratchet->nextreceiveheaderkey, KEY_SIZE,
		ratchet->nextsendheaderkey, KEY_SIZE));

	if (ratchet->ecdhkey) mr_ecdh_destroy(ratchet->ecdhkey);
	ratchet->ecdhkey = 0;
	memset(ratchet->nextrootkey, 0, KEY_SIZE);
	memset(ratchet->nextreceiveheaderkey, 0, KEY_SIZE);
	memset(ratchet->nextsendheaderkey, 0, KEY_SIZE);

	return E_SUCCESS;
}

mr_result_t chain_initialize(mr_ctx mr_ctx, _mr_chain_state * chain_state, const uint8_t* chainkey, uint32_t chainkeysize)
{
	FAILIF(!chain_state, E_INVALIDARGUMENT, "!chain_state")
	FAILIF(chainkey && chainkeysize != KEY_SIZE, E_INVALIDSIZE, "chainkey && chainkeysize != KEY_SIZE")

	if (chainkey) memcpy(chain_state->chainkey, chainkey, KEY_SIZE);
	else memset(chain_state->chainkey, 0, KEY_SIZE);

	chain_state->generation = 0;
	chain_state->oldgeneration = 0;

	memset(chain_state->oldchainkey, 0, KEY_SIZE);

	return E_SUCCESS;
}

mr_result_t chain_ratchetforsending(mr_ctx mr_ctx, _mr_chain_state * chain, uint8_t* key, uint32_t keysize, uint32_t* generation)
{
	FAILIF(!mr_ctx || !chain || !key || !generation, E_INVALIDARGUMENT, "!mr_ctx || !chain || !key || !generation")
	FAILIF(keysize != MSG_KEY_SIZE, E_INVALIDSIZE, "keysize != MSG_KEY_SIZE")

	struct {
		uint8_t nck[KEY_SIZE];
		uint8_t key[MSG_KEY_SIZE];
	} keys;
	_C(kdf_compute(mr_ctx, chain->chainkey, KEY_SIZE, _chain_context, sizeof(_chain_context), keys.nck, sizeof(keys)));

	memcpy(chain->chainkey, keys.nck, KEY_SIZE);
	memcpy(key, keys.key, MSG_KEY_SIZE);
	*generation = ++chain->generation;

	return E_SUCCESS;
}

mr_result_t chain_ratchetforreceiving(mr_ctx mr_ctx, _mr_chain_state * chain, uint32_t generation, uint8_t* key, uint32_t keysize)
{
	FAILIF(!mr_ctx || !chain || !key, E_INVALIDARGUMENT, "!mr_ctx || !chain || !key")
	FAILIF(keysize != MSG_KEY_SIZE, E_INVALIDSIZE, "keysize != MSG_KEY_SIZE")

	uint32_t gen;
	uint8_t* ck;
	int oldkeyallzeroes = keyallzeroes(chain->oldchainkey);

	// figure out if we're starting to ratchet from the chain key or the "old chain key"
	if (generation > chain->generation)
	{
		// generation is bigger than the chain gen so we start at the chain key
		gen = chain->generation;
		ck = chain->chainkey;
	}
	else
	{
		if (generation > chain->oldgeneration && !oldkeyallzeroes)
		{
			// generation is old and we have an older chain key so start from that.
			gen = chain->oldgeneration;
			ck = chain->oldchainkey;
		}
		else
		{
			return E_KEYLOST;
		}
	}

	int mustSkip = generation > chain->generation && (generation - chain->generation) > 1;
	int incrementOld = generation > chain->oldgeneration && generation <= chain->generation &&
		!oldkeyallzeroes && (generation == chain->oldgeneration + 1);

	// ratchet until ++gen == generation
	uint8_t* cku = ck;
	struct {
		uint8_t nck[KEY_SIZE];
		uint8_t key[MSG_KEY_SIZE];
	} keys;
	for (;gen < generation; gen++)
	{
		_C(kdf_compute(mr_ctx, cku, KEY_SIZE, _chain_context, sizeof(_chain_context), keys.nck, sizeof(keys)));
		cku = keys.nck;
	}

	// copy out the key
	memcpy(key, keys.key, keysize);

	// we had to skip, old chain key gets updated if its not set already
	if (mustSkip && oldkeyallzeroes)
	{
		memcpy(chain->oldchainkey, chain->chainkey, KEY_SIZE);
		chain->oldgeneration = chain->generation;
	}

	// we started with the old chain key and only went one step so udpate it
	if (incrementOld)
	{
		memcpy(chain->oldchainkey, keys.nck, KEY_SIZE);
		chain->oldgeneration++;
	}

	// if the requested generation is greater than the chain gen, update it
	if (generation > chain->generation)
	{
		memcpy(chain->chainkey, keys.nck, KEY_SIZE);
		chain->generation = gen;
	}

	return E_SUCCESS;
}