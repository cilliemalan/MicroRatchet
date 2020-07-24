#include "pch.h"
#include <microratchet.h>
#include "ecc_common.h"
#include <mbedtls/ecdsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#define TODO 0

typedef struct {
	mr_ctx mr_ctx;
	ecc_key key;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
} _mr_ecdsa_ctx;

mr_ecdsa_ctx mr_ecdsa_create(mr_ctx mr_ctx)
{
	_mr_ecdsa_ctx* ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_ecdsa_ctx), (void**)&ctx);
	if (r != MR_E_SUCCESS) return 0;

	ctx->mr_ctx = mr_ctx;
	ctx->key = (ecc_key){ 0 };
	mbedtls_entropy_init(&ctx->entropy);
	mbedtls_ctr_drbg_init(&ctx->ctr_drbg);

#ifdef MR_EMBEDDED
	_R(r, mbedtls_entropy_add_source(&ctx->entropy, mr_mbedtls_entropy_f_source, 0, 32, MBEDTLS_ENTROPY_SOURCE_STRONG));
#endif

	r = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy, 0, 0);
	if (r)
	{
		mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
		mbedtls_entropy_free(&ctx->entropy);
		mr_free(mr_ctx, ctx);
		FAILIF(r, 0, "Could not seed RNG");
	}
	return ctx;
}

mr_result mr_ecdsa_setprivatekey(mr_ecdsa_ctx _ctx, const uint8_t* privatekey, uint32_t privatekeysize)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	FAILIF(privatekeysize < 32, MR_E_INVALIDSIZE, "privatekeysize < 32");
	FAILIF(!privatekey || !ctx, MR_E_INVALIDARG, "!privatekey || !ctx");

	return ecc_load(&ctx->key, privatekey, privatekeysize);
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
	FAILIF(!publickey || !ctx, MR_E_INVALIDARG, "!publickey || !ctx");

	return ecc_generate(&ctx->key, 
		publickey, publickeyspaceavail, 
		mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
}

uint32_t mr_ecdsa_load(mr_ecdsa_ctx _ctx, const uint8_t* data, uint32_t spaceavail)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	FAILIF(!data || !ctx, MR_E_INVALIDARG, "!data || !ctx");

	return ecc_load(&ctx->key, data, spaceavail);
}

mr_result mr_ecdsa_sign(mr_ecdsa_ctx _ctx, const uint8_t* digest, uint32_t digestsize, uint8_t* signature, uint32_t signaturespaceavail)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	FAILIF(!ctx || !digest || !signature, MR_E_INVALIDARG, "!ctx || !digest || !signature");
	FAILIF(signaturespaceavail < 64, MR_E_INVALIDSIZE, "signaturespaceavail < 64");

	return ecc_sign(&ctx->key, 
		digest, digestsize, 
		signature, signaturespaceavail, 
		mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
}

mr_result mr_ecdsa_verify(mr_ecdsa_ctx _ctx, const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, uint32_t* result)
{
	_mr_ecdsa_ctx* ctx = _ctx;
	FAILIF(!ctx || !digest || !signature || !signaturesize, MR_E_INVALIDARG, "!ctx || !digest || !signature || !signaturesize");
	FAILIF(signaturesize != 64, MR_E_INVALIDSIZE, "signaturesize != 64");

	return ecc_verify(&ctx->key, signature, signaturesize, digest, digestsize, result);
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
		mr_ctx mrctx = _ctx->mr_ctx;
		mr_memzero(_ctx, sizeof(_mr_ecdsa_ctx));
		mr_free(mrctx, _ctx);
	}
}

mr_result mr_ecdsa_verify_other(const uint8_t* signature, uint32_t signaturesize, const uint8_t* digest, uint32_t digestsize, const uint8_t* publickey, uint32_t publickeysize, uint32_t* result)
{
	FAILIF(!digest || !signature || !signaturesize || !publickey, MR_E_INVALIDARG, "!digest || !signature || !signaturesize || !publickey");
	FAILIF(signaturesize != 64, MR_E_INVALIDSIZE, "signaturesize != 64");
	FAILIF(digestsize != 32, MR_E_INVALIDSIZE, "digest must be 32 bytes");
	FAILIF(publickeysize != 32, MR_E_INVALIDSIZE, "public key must be 32 bytes");

	ecc_key key;
	mbedtls_ecp_point_init(&key.Q);

	int r = ecc_import_public(publickey, publickeysize, &key.Q);

	mr_result mrr = MR_E_SUCCESS;
	if (!r)
	{
		mrr = ecc_verify(&key, signature, signaturesize, digest, digestsize, result);
	}

	mbedtls_ecp_point_free(&key.Q);
	FAILIF(r, MR_E_INVALIDOP, "could not verify the signature");
	return mrr;
}
