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

int mr_ecdh_generate(mr_ecdh_ctx _ctx, unsigned char* publickey, unsigned int publickeyspaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;
	if (publickeyspaceavail < 32) return E_INVALIDSIZE;
	if (!publickey || !ctx) return E_INVALIDARGUMENT;

	int result = ecc_generate(&ctx->key, publickey, publickeyspaceavail);
	if (result != 0) return result;
	return E_SUCCESS;
}

int mr_ecdh_load(mr_ecdh_ctx _ctx, unsigned char* data, unsigned int spaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;
	ecc_key* key = &ctx->key;
	int result = ecc_load(key, data, spaceavail);
	if (result != 0) return result;
	return E_SUCCESS;
}

int mr_ecdh_derivekey(mr_ecdh_ctx _ctx, const unsigned char* otherpublickey, unsigned int otherpublickeysize, unsigned char* derivedkey, unsigned int derivedkeyspaceavail)
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

unsigned int mr_ecdh_store_size_needed(mr_ecdh_ctx _ctx)
{
	_mr_ecdh_ctx* ctx = _ctx;
	return ecc_store_size_needed(&ctx->key.k);
}

int mr_ecdh_store(mr_ecdh_ctx _ctx, unsigned char* data, unsigned int spaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;
	int len = ecc_store_size_needed(&ctx->key.k);
	if (len < 0 || (unsigned int)len > spaceavail) return E_INVALIDSIZE;
	int result = ecc_store(&ctx->key, data, spaceavail);
	return E_SUCCESS;
}

void mr_ecdh_destroy(mr_ecdh_ctx ctx)
{
	if (ctx)
	{
		_mr_ecdh_ctx* _ctx = (_mr_ecdh_ctx*)ctx;
		mr_free(_ctx->mr_ctx, _ctx);
	}
}