#include "pch.h"
#include <microratchet.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include "ecc_common.h"

typedef struct {
	mr_ctx mr_ctx;
	ecc_key key;
} _mr_ecdh_ctx;

mr_ecdh_ctx mr_ecdh_create(mr_ctx mr_ctx)
{
	_mr_ecdh_ctx* ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_ecdh_ctx), &ctx);
	if (r != E_SUCCESS) return 0;

	ctx->mr_ctx = mr_ctx;
	memset(&ctx->key, 0, sizeof(ctx->key));
	return ctx;
}

mr_result_t mr_ecdh_generate(mr_ecdh_ctx _ctx, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;

	int result = ecc_generate(&ctx->key, publickey, publickeyspaceavail);
	if (result != 0) return result;
	return E_SUCCESS;
}

mr_result_t mr_ecdh_load(mr_ecdh_ctx _ctx, uint8_t* data, uint32_t spaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;
	ecc_key* key = &ctx->key;
	int result = ecc_load(key, data, spaceavail);
	if (result != 0) return result;
	return E_SUCCESS;
}

mr_result_t mr_ecdh_derivekey(mr_ecdh_ctx _ctx, const uint8_t* otherpublickey, uint32_t otherpublickeysize, uint8_t* derivedkey, uint32_t derivedkeyspaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;
	if (!ctx || !otherpublickey || !derivedkey) return E_INVALIDARG;
	if (otherpublickeysize != 32) return E_INVALIDSIZE;
	if (derivedkeyspaceavail < 32) return E_INVALIDSIZE;

	ecc_point pub;
	int result = ecc_import_public(otherpublickey, otherpublickeysize, &pub);
	if (result != 0) return E_INVALIDOP;

	int dummy = derivedkeyspaceavail;
	result = wc_ecc_shared_secret_ex(&ctx->key, &pub, derivedkey, &dummy);
	if (result != 0 || dummy != 32) return E_INVALIDOP;
	return E_SUCCESS;
}

uint32_t mr_ecdh_store_size_needed(mr_ecdh_ctx _ctx)
{
	_mr_ecdh_ctx* ctx = _ctx;
	return ecc_store_size_needed(&ctx->key.k);
}

mr_result_t mr_ecdh_store(mr_ecdh_ctx _ctx, uint8_t* data, uint32_t spaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;
	int len = ecc_store_size_needed(&ctx->key.k);
	if (len < 0 || (uint32_t)len > spaceavail) return E_INVALIDSIZE;
	int result = ecc_store(&ctx->key, data, spaceavail);
	return E_SUCCESS;
}


mr_result_t mr_ecdh_setprivatekey(mr_ecdh_ctx _ctx, const uint8_t* privatekey, uint32_t privatekeysize)
{
	_mr_ecdh_ctx* ctx = _ctx;
	if (privatekeysize < 32) return E_INVALIDSIZE;
	if (!privatekey || !ctx) return E_INVALIDARGUMENT;

	ecc_key* key = &ctx->key;
	int result = ecc_load(key, privatekey, privatekeysize);
	if (result != 0) return result;
	return E_SUCCESS;
}

mr_result_t mr_ecdh_getpublickey(mr_ecdh_ctx _ctx, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;
	if (publickeyspaceavail < 32) return E_INVALIDSIZE;
	if (!publickey || !ctx) return E_INVALIDARGUMENT;

	return ecc_getpublickey(&ctx->key, publickey, publickeyspaceavail);
}

void mr_ecdh_destroy(mr_ecdh_ctx ctx)
{
	if (ctx)
	{
		_mr_ecdh_ctx* _ctx = (_mr_ecdh_ctx*)ctx;
		*_ctx = (_mr_ecdh_ctx){0};
		mr_free(_ctx->mr_ctx, _ctx);
	}
}