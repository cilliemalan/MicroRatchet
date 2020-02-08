#include "pch.h"
#include <microratchet.h>
#include "ecc_common.h"

#define TODO 0

typedef struct {
	mr_ctx mr_ctx;
} _mr_ecdh_ctx;

mr_ecdh_ctx mr_ecdh_create(mr_ctx mr_ctx)
{
	_mr_ecdh_ctx* ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_ecdh_ctx), (void**)&ctx);
	if (r != MR_E_SUCCESS) return 0;

	*ctx = (_mr_ecdh_ctx){
		.mr_ctx = mr_ctx
	};
	return ctx;
}

mr_result mr_ecdh_generate(mr_ecdh_ctx _ctx, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;

	return MR_E_NOTIMPL;
}

uint32_t mr_ecdh_load(mr_ecdh_ctx _ctx, const uint8_t* data, uint32_t spaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;

	return ecc_load(TODO, data, spaceavail);
}

mr_result mr_ecdh_derivekey(mr_ecdh_ctx _ctx, const uint8_t* otherpublickey, uint32_t otherpublickeysize, uint8_t* derivedkey, uint32_t derivedkeyspaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;
	FAILIF(!ctx || !otherpublickey || !derivedkey, MR_E_INVALIDARG, "!ctx || !otherpublickey || !derivedkey")
	FAILIF(otherpublickeysize != 32, MR_E_INVALIDSIZE, "otherpublickeysize != 32")
	FAILIF(derivedkeyspaceavail < 32, MR_E_INVALIDSIZE, "derivedkeyspaceavail < 32")

	return MR_E_NOTIMPL;
}

uint32_t mr_ecdh_store_size_needed(mr_ecdh_ctx _ctx)
{
	_mr_ecdh_ctx* ctx = _ctx;

	return ecc_store_size_needed(TODO);
}

mr_result mr_ecdh_store(mr_ecdh_ctx _ctx, uint8_t* data, uint32_t spaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;

	return MR_E_NOTIMPL;
}


mr_result mr_ecdh_setprivatekey(mr_ecdh_ctx _ctx, const uint8_t* privatekey, uint32_t privatekeysize)
{
	_mr_ecdh_ctx* ctx = _ctx;
	FAILIF(privatekeysize < 32, MR_E_INVALIDSIZE, "privatekeysize < 32")
	FAILIF(!privatekey || !ctx, MR_E_INVALIDARG, "!privatekey || !ctx")

	return MR_E_NOTIMPL;
}

mr_result mr_ecdh_getpublickey(mr_ecdh_ctx _ctx, uint8_t* publickey, uint32_t publickeyspaceavail)
{
	_mr_ecdh_ctx* ctx = _ctx;
	FAILIF(publickeyspaceavail < 32, MR_E_INVALIDSIZE, "publickeyspaceavail < 32")
	FAILIF(!publickey || !ctx, MR_E_INVALIDARG, "!publickey || !ctx")

	return MR_E_NOTIMPL;
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