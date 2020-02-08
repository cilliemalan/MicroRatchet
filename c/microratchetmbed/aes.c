#include "pch.h"
#include <microratchet.h>

typedef struct {
	mr_ctx mr_ctx;
} _mr_aes_ctx;

mr_aes_ctx mr_aes_create(mr_ctx mr_ctx)
{
	_mr_aes_ctx* ctx;
	int r = mr_allocate(mr_ctx, sizeof(_mr_aes_ctx), (void**)&ctx);
	if (r != MR_E_SUCCESS) return 0;
	*ctx = (_mr_aes_ctx){
		.mr_ctx = mr_ctx
	};
	return ctx;
}

mr_result mr_aes_init(mr_aes_ctx _ctx, const uint8_t* key, uint32_t keysize)
{
	_mr_aes_ctx* ctx = _ctx;
	FAILIF(keysize != 16 && keysize != 24 && keysize != 32, MR_E_INVALIDSIZE, "keysize != 16 && keysize != 24 && keysize != 32")

	return MR_E_NOTIMPL;
}	

mr_result mr_aes_process(mr_aes_ctx _ctx, const uint8_t* data, uint32_t amount, uint8_t* output, uint32_t spaceavail)
{
	_mr_aes_ctx* ctx = _ctx;
	FAILIF(amount > spaceavail, MR_E_INVALIDSIZE, "amount > spaceavail")
	FAILIF(!data || !output || !_ctx, MR_E_INVALIDARG, "!data || !output || !_ctx")
	FAILIF(amount < 16 || spaceavail < 16, MR_E_INVALIDSIZE, "amount < 16 || spaceavail < 16")

	return MR_E_NOTIMPL;
}

void mr_aes_destroy(mr_aes_ctx ctx)
{
	if (ctx)
	{
		_mr_aes_ctx* _ctx = (_mr_aes_ctx*)ctx;
		*_ctx = (_mr_aes_ctx){ 0 };
		mr_free(_ctx->mr_ctx, _ctx);
	}
}
