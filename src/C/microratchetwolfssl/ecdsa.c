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

int mr_ecdsa_setprivatekey(mr_ecdsa_ctx _ctx, const unsigned char* privatekey, unsigned int privatekeysize)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	if (privatekeysize < 32) return E_INVALIDSIZE;
	if (!privatekey || !ctx) return E_INVALIDARGUMENT;

	ecc_key* key = &ctx->key;
	int result = ecc_load(key, privatekey, privatekeysize);
	if (result != 0) return result;
	return E_SUCCESS;
}

int mr_ecdsa_generate(mr_ecdsa_ctx _ctx, unsigned char* publickey, unsigned int publickeyspaceavail)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	if (publickeyspaceavail < 32) return E_INVALIDSIZE;
	if (!publickey || !ctx) return E_INVALIDARGUMENT;

	int result = ecc_generate(&ctx->key, publickey, publickeyspaceavail);
	if (result != 0) return result;
	return E_SUCCESS;
}

int mr_ecdsa_load(mr_ecdsa_ctx _ctx, unsigned char* data, unsigned int spaceavail)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	ecc_key* key = &ctx->key;
	int result = ecc_load(key, data, spaceavail);
	if (result != 0) return result;
	return E_SUCCESS;
}

int mr_ecdsa_sign(mr_ecdsa_ctx _ctx, const unsigned char* digest, unsigned int digestsize, unsigned char* signature, unsigned int signaturespaceavail)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	if (!ctx || !digest || !signature) return E_INVALIDARG;
	if (signaturespaceavail < 64) return E_INVALIDSIZE;

	int result = ecc_sign(&ctx->key, digest, digestsize, signature, signaturespaceavail);
	if (result != E_SUCCESS) return result;
	return E_SUCCESS;
}

int mr_ecdsa_verify(mr_ecdsa_ctx _ctx, const unsigned char* signature, unsigned int signaturesize, const unsigned char* digest, unsigned int digestsize, unsigned int* result)
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

int mr_ecdsa_store(mr_ecdsa_ctx _ctx, unsigned char* data, unsigned int spaceavail)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	int len = ecc_store_size_needed(&ctx->key.k);
	if (len < 0 || (unsigned int)len > spaceavail) return E_INVALIDSIZE;
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

int mr_ecdsa_verify_other(const unsigned char* signature, unsigned int signaturesize, const unsigned char* digest, unsigned int digestsize, const unsigned char* publickey, unsigned int publickeysize, unsigned int* result)
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
