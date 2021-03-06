#include "pch.h"
#include <microratchet.h>
#include "ecc_common.h"

typedef struct {
	mr_ctx mr_ctx;
	ecc_key key;
} _mr_ecdh_ctx;

mr_ecdh_ctx mr_ecdh_create(mr_ctx mr_ctx)
{
	ecc_initialize(mr_ctx);

	_mr_ecdh_ctx* ctx;
	mr_result r = mr_allocate(mr_ctx, sizeof(_mr_ecdh_ctx), (void**)&ctx);
	if (r != MR_E_SUCCESS) return 0;

	mr_memzero(ctx, sizeof(_mr_ecdh_ctx));
	ctx->mr_ctx = mr_ctx;
	
	r = ecc_new(&ctx->key);
	if (r != MR_E_SUCCESS)
	{
		mr_free(mr_ctx, ctx);
		return 0;
	}

	return ctx;
}

mr_result mr_ecdh_generate(mr_ecdh_ctx _ctx, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	FAILIF(!_ctx, MR_E_INVALIDARG, "!_ctx");
	_mr_ecdh_ctx* ctx = _ctx;

	return ecc_generate(&ctx->key, publickey, publickeyspaceavail);
}

uint32_t mr_ecdh_load(mr_ecdh_ctx _ctx, const uint8_t* data, uint32_t spaceavail)
{
	FAILIF(!_ctx, MR_E_INVALIDARG, "!_ctx");

	_mr_ecdh_ctx* ctx = _ctx;
	ecc_key* key = &ctx->key;
	return ecc_load(key, data, spaceavail);
}

mr_result mr_ecdh_derivekey(mr_ecdh_ctx _ctx, const uint8_t* otherpublickey, uint32_t otherpublickeysize, uint8_t* derivedkey, uint32_t derivedkeyspaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;
	FAILIF(!ctx || !otherpublickey || !derivedkey, MR_E_INVALIDARG, "!ctx || !otherpublickey || !derivedkey");
	FAILIF(otherpublickeysize != 32, MR_E_INVALIDSIZE, "otherpublickeysize != 32");
	FAILIF(derivedkeyspaceavail < 32, MR_E_INVALIDSIZE, "derivedkeyspaceavail < 32");

	return ecc_derivekey(&ctx->key, otherpublickey, otherpublickeysize, derivedkey, derivedkeyspaceavail);
}

uint32_t mr_ecdh_store_size_needed(mr_ecdh_ctx _ctx)
{
	_mr_ecdh_ctx* ctx = _ctx;
	return ecc_store_size_needed(&ctx->key);
}

mr_result mr_ecdh_store(mr_ecdh_ctx _ctx, uint8_t* data, uint32_t spaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;
	int len = ecc_store_size_needed(&ctx->key);
	FAILIF(len < 0 || (uint32_t)len > spaceavail, MR_E_INVALIDSIZE, "len < 0 || (uint32_t)len > spaceavail");
	return ecc_store(&ctx->key, data, spaceavail);
}


mr_result mr_ecdh_setprivatekey(mr_ecdh_ctx _ctx, const uint8_t* privatekey, uint32_t privatekeysize)
{
	_mr_ecdh_ctx* ctx = _ctx;
	FAILIF(privatekeysize < 32, MR_E_INVALIDSIZE, "privatekeysize < 32");
	FAILIF(!privatekey || !ctx, MR_E_INVALIDARG, "!privatekey || !ctx");

	ecc_key* key = &ctx->key;
	int r = ecc_load(key, privatekey, privatekeysize);
	FAILIF(r != 32, MR_E_INVALIDOP, "Failed to load private key");
	return MR_E_SUCCESS;
}

mr_result mr_ecdh_getpublickey(mr_ecdh_ctx _ctx, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;
	FAILIF(publickeyspaceavail < 32, MR_E_INVALIDSIZE, "publickeyspaceavail < 32");
	FAILIF(!publickey || !ctx, MR_E_INVALIDARG, "!publickey || !ctx");

	return ecc_getpublickey(&ctx->key, publickey, publickeyspaceavail);
}

void mr_ecdh_destroy(mr_ecdh_ctx ctx)
{
	if (ctx)
	{
		_mr_ecdh_ctx* _ctx = (_mr_ecdh_ctx*)ctx;

		ecc_free(&_ctx->key);

		mr_ctx mrctx = _ctx->mr_ctx;
		mr_memzero(_ctx , sizeof(_mr_ecdh_ctx));
		mr_free(mrctx, _ctx);
	}
}