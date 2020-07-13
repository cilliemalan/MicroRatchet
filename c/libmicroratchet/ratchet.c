#include "pch.h"
#include "microratchet.h"
#include "internal.h"

static uint8_t _chain_context[] = { 0x7d, 0x93, 0x96, 0x05, 0xf5, 0xb6, 0xd2, 0xe2, 0x65, 0xd0, 0xde, 0xe6, 0xe4, 0x5d, 0x7a, 0x2c };

static inline bool keyallzeroes(const uint8_t k[KEY_SIZE])
{
	for (int i = 0; i < KEY_SIZE; i++)
	{
		if (k[i]) return false;
	}
	return true;
}

mr_result ratchet_getorder(mr_ctx mr_ctx, int* indexes, uint32_t numindexes)
{
	FAILIF(!mr_ctx || !indexes, MR_E_INVALIDOP, "Some of the required arguments were null");
	FAILIF(numindexes < NUM_RATCHETS, MR_E_INVALIDSIZE, "numindexes cannot be greater than the maximum number of stored ratchets");
	_mr_ctx* ctx = (_mr_ctx*)mr_ctx;

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

	return MR_E_SUCCESS;
}

mr_result ratchet_getoldest(mr_ctx mr_ctx, _mr_ratchet_state** ratchet)
{
	FAILIF(!mr_ctx || !ratchet, MR_E_INVALIDOP, "Some of the required arguments were null");
	_mr_ctx* ctx = (_mr_ctx*)mr_ctx;

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

	FAILIF(minix < 0, MR_E_NOTFOUND, "Could not find the oldest ratchet");
	*ratchet = &ctx->ratchets[minix];
	return MR_E_SUCCESS;
}

mr_result ratchet_getsecondtolast(mr_ctx mr_ctx, _mr_ratchet_state** ratchet)
{
	FAILIF(!mr_ctx || !ratchet, MR_E_INVALIDOP, "Some of the required arguments were null");
	_mr_ctx* ctx = (_mr_ctx*)mr_ctx;

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

	if (nextmaxix < 0)
	{
		// special case where the server has just initialized.
		// it's the one case where the last ecdh key can be used without
		// including it in the message that's being sent.
		if (!ctx->config.is_client && ctx->ratchets[0].num == 1 && ctx->ratchets[1].num == 0)
		{
			*ratchet = &ctx->ratchets[0];
			return MR_E_SUCCESS;
		}
	}

	FAILIF(nextmaxix < 0, MR_E_NOTFOUND, "Could not find a second to last ratchet.");
	*ratchet = &ctx->ratchets[nextmaxix];
	return MR_E_SUCCESS;
}

mr_result ratchet_getlast(mr_ctx mr_ctx, _mr_ratchet_state** ratchet)
{
	FAILIF(!mr_ctx || !ratchet, MR_E_INVALIDOP, "Some of the required arguments were null");
	_mr_ctx* ctx = (_mr_ctx*)mr_ctx;

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

	FAILIF(maxix < 0, MR_E_NOTFOUND, "Could not find the biggest ratchet");
	*ratchet = &ctx->ratchets[maxix];
	return MR_E_SUCCESS;
}

mr_result ratchet_add(mr_ctx mr_ctx, _mr_ratchet_state* ratchet)
{
	FAILIF(!mr_ctx || !ratchet, MR_E_INVALIDOP, "Some of the required arguments were null");
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

	FAILIF(minix < 0, MR_E_NOTFOUND, "Could not find the smallest ratchet");
	if (ctx->ratchets[minix].ecdhkey) mr_ecdh_destroy(ctx->ratchets[minix].ecdhkey);
	ratchet->num = maxnum + 1;
	// TODO: below uses a lot of stack
	memcpy(&ctx->ratchets[minix], ratchet, sizeof(_mr_ratchet_state));

	return MR_E_SUCCESS;
}

void ratchet_destroy_all(_mr_ctx* ctx)
{
	for (int i = 0; i < NUM_RATCHETS; i++)
	{
		if (ctx->ratchets[i].ecdhkey)
		{
			mr_ecdh_destroy(ctx->ratchets[i].ecdhkey);
		}
		memset(&ctx->ratchets[i], 0, sizeof(ctx->ratchets[i]));
	}
}

bool ratchet_destroy(_mr_ctx* ctx, int num)
{
	if (!ctx) return false;

	for (int i = 0; i < NUM_RATCHETS; i++)
	{
		if (ctx->ratchets[i].num == num)
		{
			if (ctx->ratchets[i].ecdhkey)
			{
				mr_ecdh_destroy(ctx->ratchets[i].ecdhkey);
			}
			memset(&ctx->ratchets[i], 0, sizeof(ctx->ratchets[i]));
			return true;
		}
	}

	return false;
}

mr_result ratchet_initialize_server(mr_ctx mr_ctx,
	_mr_ratchet_state* ratchet,
	mr_ecdh_ctx previouskeypair,
	const uint8_t* rootkey, uint32_t rootkeysize,
	const uint8_t* remotepubickey, uint32_t remotepubickeysize,
	mr_ecdh_ctx keypair,
	const uint8_t* receiveheaderkey, uint32_t receiveheaderkeysize,
	const uint8_t* sendheaderkey, uint32_t sendheaderkeysize)
{
	FAILIF(!mr_ctx || !ratchet || !previouskeypair || !keypair, MR_E_INVALIDARG, "Some of the required arguments were null");
	FAILIF(previouskeypair == keypair, MR_E_INVALIDARG, "The previous key pair and the current key pair were equal");
	FAILIF(!rootkey || !remotepubickey, MR_E_INVALIDARG, "Some of the required arguments were null");
	FAILIF(rootkeysize != KEY_SIZE || remotepubickeysize != KEY_SIZE, MR_E_INVALIDSIZE, "Some of the key sizes were invalid");
	FAILIF(receiveheaderkey && receiveheaderkeysize != KEY_SIZE, MR_E_INVALIDSIZE, "Some of the key sizes were invalid");
	FAILIF(sendheaderkey && sendheaderkeysize != KEY_SIZE, MR_E_INVALIDSIZE, "Some of the key sizes were invalid");
	_mr_ctx* ctx = (_mr_ctx*)mr_ctx;

	LOG("--Initialize ECDH Ratchet");
	LOGD("Root Key:           ", rootkey, KEY_SIZE);
	LOGD("Receive Header Key: ", receiveheaderkey, KEY_SIZE);
	LOGD("Send Header Key:    ", sendheaderkey, KEY_SIZE);
	LOGD("ECDH Public:        ", remotepubickey, KEY_SIZE);

	memset(ratchet, 0, sizeof(_mr_ratchet_state));
	ratchet->num = 1;
	ratchet->ecdhkey = keypair;
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

	return MR_E_SUCCESS;
}

mr_result ratchet_initialize_client(mr_ctx mr_ctx,
	_mr_ratchet_state* ratchet1,
	_mr_ratchet_state* ratchet2,
	const uint8_t* rootkey, uint32_t rootkeysize,
	const uint8_t* remotepubickey0, uint32_t remotepubickey0size,
	const uint8_t* remotepubickey1, uint32_t remotepubickey1size,
	mr_ecdh_ctx keypair,
	const uint8_t* receiveheaderkey, uint32_t receiveheaderkeysize,
	const uint8_t* sendheaderkey, uint32_t sendheaderkeysize,
	mr_ecdh_ctx nextkeypair)
{
	FAILIF(!mr_ctx || !ratchet1 || !ratchet2 || !nextkeypair || !keypair, MR_E_INVALIDARG, "Some of the required arguments were null");
	FAILIF(!rootkey || !remotepubickey0 || !remotepubickey1, MR_E_INVALIDARG, "Some of the required arguments were null");
	FAILIF(!receiveheaderkey || !sendheaderkey, MR_E_INVALIDARG, "Some of the required arguments were null");
	FAILIF(rootkeysize != KEY_SIZE || remotepubickey0size != KEY_SIZE || remotepubickey1size != KEY_SIZE, MR_E_INVALIDSIZE, "Some of the key sizes were invalid");
	FAILIF(receiveheaderkeysize != KEY_SIZE || sendheaderkeysize != KEY_SIZE, MR_E_INVALIDSIZE, "Some of the key sizes were invalid");
	_mr_ctx* ctx = (_mr_ctx*)mr_ctx;

	LOG("--Initialize ECDH Ratchet CLIENT");
	LOGD("Root Key:           ", rootkey, KEY_SIZE);
	LOGD("Receive Header Key: ", receiveheaderkey, KEY_SIZE);
	LOGD("Send Header Key:    ", sendheaderkey, KEY_SIZE);
	LOGD("ECDH Public 0:      ", remotepubickey0, KEY_SIZE);
	LOGD("ECDH Public 1:      ", remotepubickey1, KEY_SIZE);

	memset(ratchet2, 0, sizeof(_mr_ratchet_state));
	memset(ratchet1, 0, sizeof(_mr_ratchet_state));
	ratchet1->num = 1;
	ratchet1->ecdhkey = keypair;
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

	return MR_E_SUCCESS;
}

mr_result ratchet_initialize(
	mr_ctx mr_ctx,
	_mr_ratchet_state* ratchet,
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
	FAILIF(!ratchet || !mr_ctx, MR_E_INVALIDARG, "Some of the required arguments were null");
	FAILIF(nextrootkey && nextrootkeysize != KEY_SIZE, MR_E_INVALIDSIZE, "The next root key size was invalid");
	FAILIF(receivingheaderkey && receivingheaderkeysize != KEY_SIZE, MR_E_INVALIDSIZE, "The receive header key size was invalid");
	FAILIF(receivingnextheaderkey && receivingnextheaderkeysize != KEY_SIZE, MR_E_INVALIDSIZE, "The receive next header key size was invalid");
	FAILIF(receivingchainkey && receivingchainkeysize != KEY_SIZE, MR_E_INVALIDSIZE, "The receive chain key size was invalid");
	FAILIF(sendingheaderkey && sendingheaderkeysize != KEY_SIZE, MR_E_INVALIDSIZE, "The send header key size was invalid");
	FAILIF(sendingnextheaderkey && sendingnextheaderkeysize != KEY_SIZE, MR_E_INVALIDSIZE, "The send header key size was invalid");
	FAILIF(sendingchainkey && sendingchainkeysize != KEY_SIZE, MR_E_INVALIDSIZE, "The sending chain key size was invalid");

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

	return MR_E_SUCCESS;
}

mr_result ratchet_ratchet(mr_ctx mr_ctx, _mr_ratchet_state* ratchet, _mr_ratchet_state* nextratchet, const uint8_t* remotepublickey, uint32_t remotepublickeysize, mr_ecdh_ctx keypair)
{
	FAILIF(!ratchet || !nextratchet || !remotepublickey || !keypair, MR_E_INVALIDARG, "Some of the required arguments were null");
	FAILIF(keypair == ratchet->ecdhkey, MR_E_INVALIDARG, "The key pair cannot be equal to the ratchet ECDH key");
	FAILIF(remotepublickeysize != KEY_SIZE, MR_E_INVALIDSIZE, "The remote public key size was invalid");

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

	return MR_E_SUCCESS;
}

mr_result chain_initialize(mr_ctx mr_ctx, _mr_chain_state* chain_state, const uint8_t* chainkey, uint32_t chainkeysize)
{
	FAILIF(!chain_state, MR_E_INVALIDARG, "Some of the required arguments were null");
	FAILIF(chainkey && chainkeysize != KEY_SIZE, MR_E_INVALIDSIZE, "The key size was invalid");

	if (chainkey) memcpy(chain_state->chainkey, chainkey, KEY_SIZE);
	else memset(chain_state->chainkey, 0, KEY_SIZE);

	chain_state->generation = 0;
	chain_state->oldgeneration = 0;

	memset(chain_state->oldchainkey, 0, KEY_SIZE);

	return MR_E_SUCCESS;
}

mr_result chain_ratchetforsending(mr_ctx mr_ctx, _mr_chain_state* chain, uint8_t* key, uint32_t keysize, uint32_t* generation)
{
	FAILIF(!mr_ctx || !chain || !key || !generation, MR_E_INVALIDARG, "Some of the required arguments were null");
	FAILIF(keysize != MSG_KEY_SIZE, MR_E_INVALIDSIZE, "The key size was invalid");

	struct {
		uint8_t nck[KEY_SIZE];
		uint8_t key[MSG_KEY_SIZE];
	} keys;
	_C(kdf_compute(mr_ctx, chain->chainkey, KEY_SIZE, _chain_context, sizeof(_chain_context), keys.nck, sizeof(keys)));

	memcpy(chain->chainkey, keys.nck, KEY_SIZE);
	memcpy(key, keys.key, MSG_KEY_SIZE);
	*generation = ++chain->generation;

	return MR_E_SUCCESS;
}

mr_result chain_ratchetforreceiving(mr_ctx mr_ctx, _mr_chain_state* chain, uint32_t generation, uint8_t* key, uint32_t keysize)
{
	FAILIF(!mr_ctx || !chain || !key, MR_E_INVALIDARG, "Some of the required arguments were null");
	FAILIF(keysize != MSG_KEY_SIZE, MR_E_INVALIDSIZE, "The key size was invalid");

	uint32_t gen = 0;
	uint8_t* ck = 0;
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
			FAILIF(true, MR_E_NOTFOUND, "The requested ratchet key has been lost");
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
	} keys = { 0 };
	for (; gen < generation; gen++)
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

	return MR_E_SUCCESS;
}