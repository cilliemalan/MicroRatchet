#include "pch.h"
#include "microratchet.h"
#include "internal.h"


void mr_sha_init_cb(int status, mr_sha_ctx ctx, mr_ctx mr_ctx)
{
	_mr_ctx* _ctx = (_mr_ctx*)(mr_ctx);
	_ctx->next(status, _ctx);
}

void mr_sha_process_cb(int status, mr_sha_ctx ctx, mr_ctx mr_ctx)
{
	_mr_ctx* _ctx = (_mr_ctx*)(mr_ctx);
	_ctx->next(status, _ctx);
}

void mr_sha_compute_cb(int status, mr_sha_ctx ctx, mr_ctx mr_ctx)
{
	_mr_ctx* _ctx = (_mr_ctx*)(mr_ctx);
	_ctx->next(status, _ctx);
}

void mr_aes_init_cb(int status, mr_aes_ctx ctx, mr_ctx mr_ctx)
{
	_mr_ctx* _ctx = (_mr_ctx*)(mr_ctx);
	_ctx->next(status, _ctx);
}

void mr_aes_process_cb(int status, mr_aes_ctx ctx, mr_ctx mr_ctx)
{
	_mr_ctx* _ctx = (_mr_ctx*)(mr_ctx);
	_ctx->next(status, _ctx);
}

void mr_gmac_init_cb(int status, mr_gmac_ctx ctx, mr_ctx mr_ctx)
{
	_mr_ctx* _ctx = (_mr_ctx*)(mr_ctx);
	_ctx->next(status, _ctx);
}

void mr_gmac_process_cb(int status, mr_gmac_ctx ctx, mr_ctx mr_ctx)
{
	_mr_ctx* _ctx = (_mr_ctx*)(mr_ctx);
	_ctx->next(status, _ctx);
}

void mr_gmac_compute_cb(int status, mr_gmac_ctx ctx, mr_ctx mr_ctx)
{
	_mr_ctx* _ctx = (_mr_ctx*)(mr_ctx);
	_ctx->next(status, _ctx);
}

void mr_ecdh_generate_cb(int status, mr_ecdh_ctx ctx, mr_ctx mr_ctx)
{
	_mr_ctx* _ctx = (_mr_ctx*)(mr_ctx);
	_ctx->next(status, _ctx);
}

void mr_ecdh_load_cb(int status, mr_ecdh_ctx ctx, mr_ctx mr_ctx)
{
	_mr_ctx* _ctx = (_mr_ctx*)(mr_ctx);
	_ctx->next(status, _ctx);
}

void mr_ecdh_derivekey_cb(int status, mr_ecdh_ctx ctx, mr_ctx mr_ctx)
{
	_mr_ctx* _ctx = (_mr_ctx*)(mr_ctx);
	_ctx->next(status, _ctx);
}

void mr_ecdh_store_cb(int status, mr_ecdh_ctx ctx, mr_ctx mr_ctx)
{
	_mr_ctx* _ctx = (_mr_ctx*)(mr_ctx);
	_ctx->next(status, _ctx);
}

void mr_ecdsa_generate_cb(int status, mr_ecdsa_ctx ctx, mr_ctx mr_ctx)
{
	_mr_ctx* _ctx = (_mr_ctx*)(mr_ctx);
	_ctx->next(status, _ctx);
}

void mr_ecdsa_load_cb(int status, mr_ecdsa_ctx ctx, mr_ctx mr_ctx)
{
	_mr_ctx* _ctx = (_mr_ctx*)(mr_ctx);
	_ctx->next(status, _ctx);
}

void mr_ecdsa_sign_cb(int status, mr_ecdsa_ctx ctx, mr_ctx mr_ctx)
{
	_mr_ctx* _ctx = (_mr_ctx*)(mr_ctx);
	_ctx->next(status, _ctx);
}

void mr_ecdsa_verify_cb(int status, mr_ecdsa_ctx ctx, mr_ctx mr_ctx)
{
	_mr_ctx* _ctx = (_mr_ctx*)(mr_ctx);
	_ctx->next(status, _ctx);
}

void mr_ecdsa_store_cb(int status, mr_ecdsa_ctx ctx, mr_ctx mr_ctx)
{
	_mr_ctx* _ctx = (_mr_ctx*)(mr_ctx);
	_ctx->next(status, _ctx);
}

void mr_ecdsa_verify_other_cb(int status, mr_ecdsa_ctx ctx, mr_ctx mr_ctx)
{
	_mr_ctx* _ctx = (_mr_ctx*)(mr_ctx);
	_ctx->next(status, _ctx);
}

void mr_rng_generate_cb(int status, mr_rng_ctx ctx, mr_ctx mr_ctx)
{
	_mr_ctx* _ctx = (_mr_ctx*)(mr_ctx);
	_ctx->next(status, _ctx);
}
