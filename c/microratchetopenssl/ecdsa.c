#include "pch.h"
#include <microratchet.h>
#include "ecc_common.h"

typedef struct {
	mr_ctx mr_ctx;
	ecc_key key;
} _mr_ecdsa_ctx;

mr_ecdsa_ctx mr_ecdsa_create(mr_ctx mr_ctx)
{
	_mr_ecdsa_ctx* ctx;
	mr_result r = mr_allocate(mr_ctx, sizeof(_mr_ecdsa_ctx), (void**)&ctx);
	if (r != MR_E_SUCCESS) return 0;

	memset(ctx, 0, sizeof(_mr_ecdsa_ctx));
	ctx->mr_ctx = mr_ctx;

	r = ecc_new(&ctx->key);
	if (r != MR_E_SUCCESS)
	{
		mr_free(mr_ctx, ctx);
		return 0;
	}

	return ctx;
}

mr_result mr_ecdsa_setprivatekey(mr_ecdsa_ctx _ctx, const uint8_t* privatekey, uint32_t privatekeysize)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	FAILIF(privatekeysize < 32, MR_E_INVALIDSIZE, "privatekeysize < 32");
	FAILIF(!privatekey || !ctx, MR_E_INVALIDARG, "!privatekey || !ctx");

	ecc_key* key = &ctx->key;
	int result = ecc_load(key, privatekey, privatekeysize);
	if (result != 0) return result;
	return MR_E_SUCCESS;
}

mr_result mr_ecdsa_getpublickey(mr_ecdsa_ctx _ctx, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	FAILIF(publickeyspaceavail < 32, MR_E_INVALIDSIZE, "publickeyspaceavail < 32");
	FAILIF(!publickey || !ctx, MR_E_INVALIDARG, "!publickey || !ctx");

	return ecc_getpublickey(&ctx->key, publickey, publickeyspaceavail);
}

mr_result mr_ecdsa_generate(mr_ecdsa_ctx _ctx, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	_mr_ecdsa_ctx* ctx = _ctx;

	return ecc_generate(&ctx->key, publickey, publickeyspaceavail);
}

uint32_t mr_ecdsa_load(mr_ecdsa_ctx _ctx, const uint8_t* data, uint32_t spaceavail)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	ecc_key* key = &ctx->key;
	return ecc_load(key, data, spaceavail);
}

mr_result mr_ecdsa_sign(mr_ecdsa_ctx _ctx, const uint8_t* digest, uint32_t digestsize, uint8_t* signature, uint32_t signaturespaceavail)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	FAILIF(!ctx || !digest || !signature, MR_E_INVALIDARG, "!ctx || !digest || !signature");
	FAILIF(signaturespaceavail < 64, MR_E_INVALIDSIZE, "signaturespaceavail < 64");

	return ecc_sign(&ctx->key, digest, digestsize, signature, signaturespaceavail);
}

uint32_t mr_ecdsa_store_size_needed(mr_ecdsa_ctx _ctx)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	return ecc_store_size_needed(&ctx->key);
}

mr_result mr_ecdsa_store(mr_ecdsa_ctx _ctx, uint8_t* data, uint32_t spaceavail)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	int len = ecc_store_size_needed(&ctx->key);
	FAILIF(len < 0 || (uint32_t)len > spaceavail, MR_E_INVALIDSIZE, "len < 0 || (uint32_t)len > spaceavail");
	return ecc_store(&ctx->key, data, spaceavail);
}

void mr_ecdsa_destroy(mr_ecdsa_ctx ctx)
{
	if (ctx)
	{
		_mr_ecdsa_ctx* _ctx = (_mr_ecdsa_ctx*)ctx;

		ecc_free(&_ctx->key);

		memset(_ctx , 0, sizeof(_mr_ecdsa_ctx));
		mr_free(_ctx->mr_ctx, _ctx);
	}
}

mr_result mr_ecdsa_verify_other(const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, const uint8_t* publickey, uint32_t publickeysize, uint32_t* result)
{
	return ecc_verify_other(signature, signaturesize, digest, digestsize, publickey, publickeysize, result);
}
