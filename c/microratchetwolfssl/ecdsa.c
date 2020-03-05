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
	int r = mr_allocate(mr_ctx, sizeof(_mr_ecdsa_ctx), (void**)&ctx);
	if (r != MR_E_SUCCESS) return 0;

	ctx->mr_ctx = mr_ctx;
	memset(&ctx->key, 0, sizeof(ctx->key));
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

	int result = ecc_generate(&ctx->key, publickey, publickeyspaceavail);
	if (result != 0) return result;
	return MR_E_SUCCESS;
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

	int result = ecc_sign(&ctx->key, digest, digestsize, signature, signaturespaceavail);
	if (result != MR_E_SUCCESS) return result;
	return MR_E_SUCCESS;
}

mr_result mr_ecdsa_verify(mr_ecdsa_ctx _ctx, const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, uint32_t* result)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	FAILIF(!ctx || !digest || !signature || !signaturesize, MR_E_INVALIDARG, "!ctx || !digest || !signature || !signaturesize");
	FAILIF(signaturesize != 64, MR_E_INVALIDSIZE, "signaturesize != 64");

	int res = ecc_verify(&ctx->key, signature, signaturesize, digest, digestsize, result);
	if (res != MR_E_SUCCESS) return res;
	return MR_E_SUCCESS;
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
	int result = ecc_store(&ctx->key, data, spaceavail);
	if (result != MR_E_SUCCESS) return result;
	return MR_E_SUCCESS;
}

void mr_ecdsa_destroy(mr_ecdsa_ctx ctx)
{
	if (ctx)
	{
		_mr_ecdsa_ctx* _ctx = (_mr_ecdsa_ctx*)ctx;
		*_ctx = (_mr_ecdsa_ctx){ 0 };
		mr_free(_ctx->mr_ctx, _ctx);
	}
}

mr_result mr_ecdsa_verify_other(const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, const uint8_t* publickey, uint32_t publickeysize, uint32_t* result)
{
	ecc_key key;
	memset(&key, 0, sizeof(key));
	key.type = ECC_PUBLICKEY;
	int res = wc_ecc_set_curve(&key, 32, ECC_SECP256R1);
	FAILIF(res != 0, MR_E_INVALIDOP, "res != 0");

	res = ecc_import_public(publickey, publickeysize, &key.pubkey);
	FAILIF(res != 0, MR_E_INVALIDOP, "res != 0");

	res = ecc_verify(&key, signature, signaturesize, digest, digestsize, result);
	if (res != MR_E_SUCCESS) return res;

	return MR_E_SUCCESS;
}
