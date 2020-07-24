#include "pch.h"
#include <microratchet.h>
#include "ecc_common.h"
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

typedef struct {
	mr_ctx mr_ctx;
	ecc_key key;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
} _mr_ecdh_ctx;

mr_ecdh_ctx mr_ecdh_create(mr_ctx mr_ctx)
{
	FAILIF(!mr_ctx, 0, "mr_ctx must be provided");

	_mr_ecdh_ctx* ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_ecdh_ctx), (void**)&ctx);
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

mr_result mr_ecdh_generate(mr_ecdh_ctx _ctx, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	FAILIF(!_ctx, MR_E_INVALIDARG, "ctx must be provided");

	_mr_ecdh_ctx* ctx = _ctx;

	mr_result r = ecc_generate(&ctx->key, publickey, publickeyspaceavail, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
	if (r) return r;

	return MR_E_SUCCESS;
}

uint32_t mr_ecdh_load(mr_ecdh_ctx _ctx, const uint8_t* data, uint32_t amt)
{
	_mr_ecdh_ctx* ctx = _ctx;
	FAILIF(!ctx, MR_E_INVALIDARG, "ctx is null");
	FAILIF(!data, MR_E_INVALIDARG, "data is null");
	FAILIF(!amt, MR_E_INVALIDARG, "amt is 0");

	return ecc_load(&ctx->key, data, amt);
}

mr_result mr_ecdh_derivekey(mr_ecdh_ctx _ctx, const uint8_t* otherpublickey, uint32_t otherpublickeysize, uint8_t* derivedkey, uint32_t derivedkeyspaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;
	FAILIF(!ctx || !otherpublickey || !derivedkey, MR_E_INVALIDARG, "!ctx || !otherpublickey || !derivedkey");
	FAILIF(otherpublickeysize != 32, MR_E_INVALIDSIZE, "otherpublickeysize != 32");
	FAILIF(derivedkeyspaceavail < 32, MR_E_INVALIDSIZE, "derivedkeyspaceavail < 32");

	mp_int z;
	ecc_point Q;
	mbedtls_mpi_init(&z);
	mbedtls_ecp_point_init(&Q);

	int r = ecc_import_public(otherpublickey, otherpublickeysize, &Q);
	if (!r)
	{
		r = mbedtls_ecdh_compute_shared(&secp256r1_gp, &z, &Q, &ctx->key.d, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
		if (!r)
		{
			r = mbedtls_mpi_write_binary(&z, derivedkey, 32);
		}
	}

	mbedtls_mpi_free(&z);
	mbedtls_ecp_point_free(&Q);

	FAILIF(r, MR_E_INVALIDOP, "failed to compute shared secret");
	return MR_E_SUCCESS;
}

uint32_t mr_ecdh_store_size_needed(mr_ecdh_ctx _ctx)
{
	_mr_ecdh_ctx* ctx = _ctx;

	return ecc_store_size_needed(&ctx->key);
}

mr_result mr_ecdh_store(mr_ecdh_ctx _ctx, uint8_t* data, uint32_t spaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;
	FAILIF(!ctx, MR_E_INVALIDARG, "ctx is null");
	FAILIF(!data, MR_E_INVALIDARG, "data is null");
	FAILIF(!spaceavail, MR_E_INVALIDARG, "spaceavail is 0");

	return ecc_store(&ctx->key, data, spaceavail);
}


mr_result mr_ecdh_setprivatekey(mr_ecdh_ctx _ctx, const uint8_t* privatekey, uint32_t privatekeysize)
{
	_mr_ecdh_ctx* ctx = _ctx;
	FAILIF(privatekeysize < 32, MR_E_INVALIDSIZE, "privatekeysize < 32");
	FAILIF(!privatekey || !ctx, MR_E_INVALIDARG, "!privatekey || !ctx");

	int r = ecc_load(&ctx->key, privatekey, 32);
	FAILIF(r != 32, MR_E_INVALIDOP, "Could not load private key");
	return MR_E_SUCCESS;
}

mr_result mr_ecdh_getpublickey(mr_ecdh_ctx _ctx, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;
	FAILIF(publickeyspaceavail < 32, MR_E_INVALIDSIZE, "publickeyspaceavail < 32");
	FAILIF(!publickey || !ctx, MR_E_INVALIDARG, "!publickey || !ctx");

	return ecc_getpublickey(&ctx->key, publickey, publickeyspaceavail);
}

void mr_ecdh_destroy(mr_ecdh_ctx _ctx)
{
	if (_ctx)
	{
		_mr_ecdh_ctx* ctx = (_mr_ecdh_ctx*)_ctx;
		mr_ctx mrctx = ctx->mr_ctx;
		mr_memzero(ctx, sizeof(_mr_ecdh_ctx));
		mbedtls_entropy_free(&ctx->entropy);
		mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
		mr_free(mrctx, ctx);
	}
}