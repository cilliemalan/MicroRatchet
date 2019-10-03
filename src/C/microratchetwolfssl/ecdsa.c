#include "pch.h"
#include <microratchet.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include "ecc_common.h"

typedef struct {
	mr_ctx mr_ctx;
	ecc_key key;
} _mr_ecdsa_ctx;

mr_ecdsa_ctx mr_ecdsa_create(mr_ctx mr_ctx)
{
	_mr_ecdsa_ctx* ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_ecdsa_ctx), &ctx);
	if (r != E_SUCCESS) return 0;

	ctx->mr_ctx = mr_ctx;
	memset(&ctx->key, 0, sizeof(ctx->key));
	return ctx;
}

mr_result_t mr_ecdsa_setprivatekey(mr_ecdsa_ctx _ctx, const uint8_t* privatekey, uint32_t privatekeysize)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	if (privatekeysize < 32) return E_INVALIDSIZE;
	if (!privatekey || !ctx) return E_INVALIDARGUMENT;

	ecc_key* key = &ctx->key;
	int result = ecc_load(key, privatekey, privatekeysize);
	if (result != 0) return result;
	return E_SUCCESS;
}

mr_result_t mr_ecdsa_getpublickey(mr_ecdsa_ctx _ctx, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	if (publickeyspaceavail < 32) return E_INVALIDSIZE;
	if (!publickey || !ctx) return E_INVALIDARGUMENT;

	return ecc_getpublickey(&ctx->key, publickey, publickeyspaceavail);
}

mr_result_t mr_ecdsa_generate(mr_ecdsa_ctx _ctx, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	_mr_ecdsa_ctx* ctx = _ctx;

	int result = ecc_generate(&ctx->key, publickey, publickeyspaceavail);
	if (result != 0) return result;
	return E_SUCCESS;
}

mr_result_t mr_ecdsa_load(mr_ecdsa_ctx _ctx, uint8_t* data, uint32_t spaceavail)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	ecc_key* key = &ctx->key;
	int result = ecc_load(key, data, spaceavail);
	if (result != 0) return result;
	return E_SUCCESS;
}

mr_result_t mr_ecdsa_sign(mr_ecdsa_ctx _ctx, const uint8_t* digest, uint32_t digestsize, uint8_t* signature, uint32_t signaturespaceavail)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	if (!ctx || !digest || !signature) return E_INVALIDARG;
	if (signaturespaceavail < 64) return E_INVALIDSIZE;

	int result = ecc_sign(&ctx->key, digest, digestsize, signature, signaturespaceavail);
	if (result != E_SUCCESS) return result;
	return E_SUCCESS;
}

mr_result_t mr_ecdsa_verify(mr_ecdsa_ctx _ctx, const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, uint32_t* result)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	if (!ctx || !digest || !signature || !signaturesize) return E_INVALIDARG;
	if (signaturesize != 64) return E_INVALIDSIZE;

	int res = ecc_verify(&ctx->key, signature, signaturesize, digest, digestsize, result);
	if (res != E_SUCCESS) return res;
	return E_SUCCESS;
}

int mr_ecdsa_store_size_needed(mr_ecdsa_ctx _ctx)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	return ecc_store_size_needed(&ctx->key.k);
}

mr_result_t mr_ecdsa_store(mr_ecdsa_ctx _ctx, uint8_t* data, uint32_t spaceavail)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	int len = ecc_store_size_needed(&ctx->key.k);
	if (len < 0 || (uint32_t)len > spaceavail) return E_INVALIDSIZE;
	int result = ecc_store(&ctx->key, data, spaceavail);
	if (result != E_SUCCESS) return result;
	return E_SUCCESS;
}

void mr_ecdsa_destroy(mr_ecdsa_ctx ctx)
{
	if (ctx)
	{
		_mr_ecdsa_ctx* _ctx = (_mr_ecdsa_ctx*)ctx;
		mr_free(_ctx->mr_ctx, _ctx);
	}
}

mr_result_t mr_ecdsa_verify_other(const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, const uint8_t* publickey, uint32_t publickeysize, uint32_t* result)
{
	ecc_key key;
	memset(&key, 0, sizeof(key));
	key.type = ECC_PUBLICKEY;
	int res = wc_ecc_set_curve(&key, 32, ECC_SECP256R1);
	if (res != 0) return E_INVALIDOP;

	res = ecc_import_public(publickey, publickeysize, &key.pubkey);
	if (res != 0) return E_INVALIDOP;

	res = ecc_verify(&key, signature, signaturesize, digest, digestsize, result);
	if (res != E_SUCCESS) return res;

	return E_SUCCESS;
}
