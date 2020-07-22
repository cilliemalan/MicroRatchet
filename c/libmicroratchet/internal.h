#pragma once

#include "microratchet.h"

#ifndef MR_DEBUG
#if defined(DEBUG) || defined(_DEBUG)
#define MR_DEBUG 1
#else
#define MR_DEBUG 0
#endif
#endif

#ifndef MR_TRACE
#define MR_TRACE 0
#endif

#ifndef MR_TRACE_DATA
#define MR_TRACE_DATA 0
#endif

#if MR_DEBUG && !defined(DEBUG)
#define DEBUG
#endif

#if MR_DEBUG && !defined(_DEBUG)
#define _DEBUG
#endif

#if !defined(MR_ASSERT)
#define MR_ASSERT(a)
#endif

#if !defined(MR_WRITE)
#define MR_WRITE(a, b)
#endif

#if !defined(MR_ABORT)
#define MR_ABORT()
#endif

#if defined(__amd64__) || defined(__x86_64__) || defined(_M_AMD64)
#define MR_X64
#endif

#if defined(_MSC_VER)

// atomic compare exchange
#include <intrin.h>
#ifdef MR_X64
#define ATOMIC_COMPARE_EXCHANGE(a, b, c) _InterlockedCompareExchange64((__int64 volatile *)&(a), (__int64)(b), (__int64)(c))
#define ATOMIC_INCREMENT(a) _InterlockedIncrement64((__int64 volatile *)&(a))
#define ATOMIC_DECREMENT(a) _InterlockedDecrement64((__int64 volatile *)&(a))
#else
#define ATOMIC_COMPARE_EXCHANGE(a, b, c) _InterlockedCompareExchange((__int32 volatile *)&(a), (__int32)(b), (__int32)(c))
#define ATOMIC_INCREMENT(a) _InterlockedIncrement((__int32 volatile *)&(a))
#define ATOMIC_DECREMENT(a) _InterlockedIncrement((__int32 volatile *)&(a))
#endif

#define STATIC_ASSERT(e, r) static_assert(e, r)
#define MR_ALIGN(n) __declspec(align(n))
#define MR_HTON _byteswap_ulong

#elif defined(__GNUC__) || defined(__clang__)

#define ATOMIC_COMPARE_EXCHANGE(a, b, c) __atomic_compare_exchange_n((size_t*)&(a), (size_t*)&(c), (size_t)(b), __ATOMIC_ACQ_REL)
#define ATOMIC_INCREMENT(a) __atomic_add_fetch((ptrdiff_t*)&(a), 1, __ATOMIC_ACQ_REL)
#define ATOMIC_DECREMENT(a) __atomic_sub_fetch((ptrdiff_t*)&(a), 1, __ATOMIC_ACQ_REL)
#define STATIC_ASSERT(e,r) _Static_assert(e, r)
#define MR_ALIGN(n) __attribute__((aligned(n))
#define MR_HTON __builtin_bswap32

#else

static inline size_t _mr_nonatomic_compare_exchange(volatile size_t* a, size_t b, size_t c)
{
	size_t r = *a;
	if (r == c) {
		*a = b;
	}
	return r;
}

#define ATOMIC_COMPARE_EXCHANGE(a, b, c) _mr_nonatomic_compare_exchange((size_t*)&(a),(b),(c))
#define ATOMIC_INCREMENT(a) (a)++
#define STATIC_ASSERT(e, r)
#define MR_ALIGN(n)
#define MR_HTON(x) (uint32_t)(\
	((((uint32_t)(x)) >> 24) & 0xff) | \
	((((uint32_t)(x)) >> 16) & 0xff) | \
	((((uint32_t)(x)) >> 8) & 0xff) | \
	((((uint32_t)(x)) >> 0) & 0xff))

#endif

#define KEY_SIZE 32
#define MSG_KEY_SIZE 16
#define INITIALIZATION_NONCE_SIZE 16
#define NONCE_SIZE 4
#define MAC_SIZE 12
#define ECNUM_SIZE 32
#define SIGNATURE_SIZE (ECNUM_SIZE  +ECNUM_SIZE)
#define NUM_RATCHETS 5
#define HEADERIV_SIZE 16
#define DIGEST_SIZE 32
#define MACIV_SIZE 16
#define MIN_PAYLOAD_SIZE (HEADERIV_SIZE)
#define OVERHEAD_WITHOUT_ECDH (NONCE_SIZE + MAC_SIZE)
#define OVERHEAD_WITH_ECDH (OVERHEAD_WITHOUT_ECDH + ECNUM_SIZE)
#define INIT_REQ_MSG_SIZE (INITIALIZATION_NONCE_SIZE + ECNUM_SIZE*2 + SIGNATURE_SIZE + MAC_SIZE)
#define INIT_RES_MSG_SIZE (INITIALIZATION_NONCE_SIZE*2 + ECNUM_SIZE*4 + SIGNATURE_SIZE + MAC_SIZE)
#define MIN_MESSAGE_SIZE (OVERHEAD_WITHOUT_ECDH + MIN_PAYLOAD_SIZE)
#define MIN_MESSAGE_SIZE_WITH_ECDH (OVERHEAD_WITH_ECDH + MIN_PAYLOAD_SIZE)

#ifdef _C
#undef _C
#endif

#ifdef _R
#undef _R
#endif

// check the result and return if not successful
#define _C(x) do { int __r = x; if(__r != MR_E_SUCCESS) return __r; } while (0)

// if (r == success) r = x
#define _R(r, x) do { if (r == MR_E_SUCCESS) r = x; } while (0)

typedef struct _mr_initialization_state_server {
	uint8_t nextinitializationnonce[INITIALIZATION_NONCE_SIZE];
	// the order of these is important
	uint8_t rootkey[KEY_SIZE];
	uint8_t firstsendheaderkey[KEY_SIZE];
	uint8_t firstreceiveheaderkey[KEY_SIZE];

	mr_ecdh_ctx localratchetstep0;
	mr_ecdh_ctx localratchetstep1;
	uint8_t clientpublickey[ECNUM_SIZE];
} _mr_initialization_state_server;

typedef struct _mr_initialization_state_client {
	uint8_t initializationnonce[INITIALIZATION_NONCE_SIZE];
	mr_ecdh_ctx localecdhforinit;
} _mr_initialization_state_client;

typedef struct _mr_initialization_state {
	bool initialized;
	union {
		_mr_initialization_state_server* server;
		_mr_initialization_state_client* client;
	};
} _mr_initialization_state;

typedef struct _mr_chain_state {
	uint32_t generation;
	uint8_t chainkey[KEY_SIZE];
	uint32_t oldgeneration;
	uint8_t oldchainkey[KEY_SIZE];
} _mr_chain_state;

typedef struct _mr_ratchet_state {
	uint32_t num;
	mr_ecdh_ctx ecdhkey;
	uint8_t nextrootkey[KEY_SIZE];
	uint8_t sendheaderkey[KEY_SIZE];
	uint8_t nextsendheaderkey[KEY_SIZE];
	uint8_t receiveheaderkey[KEY_SIZE];
	uint8_t nextreceiveheaderkey[KEY_SIZE];
	_mr_chain_state sendingchain;
	_mr_chain_state receivingchain;
} _mr_ratchet_state;

typedef struct s_mr_ctx {
	mr_config config;
	mr_sha_ctx sha_ctx;
	mr_rng_ctx rng_ctx;
	_mr_initialization_state init;
	_mr_ratchet_state ratchets[NUM_RATCHETS];
	mr_ecdsa_ctx identity;
	bool owns_identity;
	void* highlevel;
} _mr_ctx;

typedef struct _mr_aesctr_ctx {
	mr_aes_ctx aes_ctx;
	uint8_t ctr[16];
	uint32_t ctrix;
} _mr_aesctr_ctx;

#ifdef __cplusplus
extern "C" {
#endif

	// AES KDF
	mr_result kdf_compute(mr_ctx mr_ctx, const uint8_t* key, uint32_t keylen, const uint8_t* info, uint32_t infolen, uint8_t* output, uint32_t spaceavail);

	// AES CTR
	mr_result aesctr_init(_mr_aesctr_ctx* ctx, mr_aes_ctx aes, const uint8_t* iv, uint32_t ivsize);
	mr_result aesctr_process(_mr_aesctr_ctx* ctx, const uint8_t* data, uint32_t amount, uint8_t* output, uint32_t spaceavail);

	// ratchetings
	mr_result ratchet_getorder(mr_ctx mr_ctx, int* indexes, uint32_t numindexes);
	mr_result ratchet_getoldest(mr_ctx mr_ctx, _mr_ratchet_state** ratchet);
	mr_result ratchet_getsecondtolast(mr_ctx mr_ctx, _mr_ratchet_state** ratchet);
	mr_result ratchet_getlast(mr_ctx mr_ctx, _mr_ratchet_state** ratchet);
	mr_result ratchet_add(mr_ctx mr_ctx, _mr_ratchet_state* ratchet);
	void ratchet_destroy_all(_mr_ctx* ctx);
	bool ratchet_destroy(_mr_ctx* ctx, int num);
	mr_result ratchet_initialize_server(mr_ctx mr_ctx,
		_mr_ratchet_state* ratchet,
		mr_ecdh_ctx previouskeypair,
		const uint8_t* rootkey, uint32_t rootkeysize,
		const uint8_t* remotepubickey, uint32_t remotepubickeysize,
		mr_ecdh_ctx keypair,
		const uint8_t* receiveheaderkey, uint32_t receiveheaderkeysize,
		const uint8_t* sendheaderkey, uint32_t sendheaderkeysize);
	mr_result ratchet_initialize_client(mr_ctx mr_ctx,
		_mr_ratchet_state* ratchet1,
		_mr_ratchet_state* ratchet2,
		const uint8_t* rootkey, uint32_t rootkeysize,
		const uint8_t* remotepubickey0, uint32_t remotepubickey0size,
		const uint8_t* remotepubickey1, uint32_t remotepubickey1size,
		mr_ecdh_ctx keypair,
		const uint8_t* receiveheaderkey, uint32_t receiveheaderkeysize,
		const uint8_t* sendheaderkey, uint32_t sendheaderkeysize,
		mr_ecdh_ctx nextkeypair);
	mr_result ratchet_initialize(
		mr_ctx mr_ctx,
		_mr_ratchet_state* ratchet,
		uint32_t num,
		mr_ecdh_ctx ecdhkey,
		const uint8_t* nextrootkey, uint32_t nextrootkeysize,
		uint32_t receivinggeneration,
		const uint8_t* receivingheaderkey, uint32_t receivingheaderkeysize,
		const uint8_t* receivingnextheaderkey, uint32_t receivingnextheaderkeysize,
		const uint8_t* receivingchainkey, uint32_t receivingchainkeysize,
		uint32_t sendinggeneration,
		const uint8_t* sendingheaderkey, uint32_t sendingheaderkeysize,
		const uint8_t* sendingnextheaderkey, uint32_t sendingnextheaderkeysize,
		const uint8_t* sendingchainkey, uint32_t sendingchainkeysize);
	mr_result ratchet_ratchet(mr_ctx mr_ctx, _mr_ratchet_state* ratchet, _mr_ratchet_state* nextratchet, const uint8_t* remotepublickey, uint32_t remotepublickeysize, mr_ecdh_ctx keypair);
	mr_result chain_initialize(mr_ctx mr_ctx, _mr_chain_state* chain_state, const uint8_t* chainkey, uint32_t chainkeysize);
	mr_result chain_ratchetforsending(mr_ctx mr_ctx, _mr_chain_state* chain, uint8_t* key, uint32_t keysize, uint32_t* generation);
	mr_result chain_ratchetforreceiving(mr_ctx mr_ctx, _mr_chain_state* chain, uint32_t generation, uint8_t* key, uint32_t keysize);

	void mr_memcpy(void* dst, const void* src, size_t amt);
	void mr_memzero(void* dst, size_t amt);

	void _mrlogctxid(mr_ctx ctx);
	void _mrloghex(const uint8_t* data, uint32_t datalen);


#ifdef MR_WRITE_PRINTF
	void mr_write_printf(const char* msg, size_t amt);
#endif

#ifdef __cplusplus
}
#endif

#if MR_DEBUG || MR_TRACE || MR_TRACE_DATA

#define MR_STRINGIZE(x) MR_STRINGIZE2(x)
#define MR_STRINGIZE2(x) #x
#define __LINE_STRING__ MR_STRINGIZE(__LINE__)

#define MR_WRITE1(msg) do { static const char __msg[] = msg; MR_WRITE(msg, sizeof(msg) - 1); } while(0)

#endif

// fail messages to fail a function with a reason message
#if MR_DEBUG
#define DEBUGMSG(message) MR_WRITE1(message "\n")
#define DEBUGMSGCTX(ctx, message) do { _mrlogctxid(ctx); MR_WRITE1(" " message "\n"); } while(0)
#define FAILIF(condition, error, messageonfailure) if (condition) { DEBUGMSG(__FILE__ ":" __LINE_STRING__ " " messageonfailure "\n"); return (error); }
#define FAILMSGNOEXIT(messageonfailure) DEBUGMSG(__FILE__ ":" __LINE_STRING__ " " messageonfailure "\n");
#define FAILMSG(error, messageonfailure) FAILMSGNOEXIT(messageonfailure); return (error);
#else
#define DEBUGMSG(message)
#define DEBUGMSGCTX(ctx, message)
#define FAILIF(condition, error, messageonfailure) if (condition) { return (error); }
#define FAILMSGNOEXIT(error, messageonfailure) 
#define FAILMSG(error, messageonfailure) return (error);
#endif

// trace messages to debug internals
#if MR_TRACE
#define TRACEMSG(msg) MR_WRITE1(msg "\n")
#define TRACEMSGCTX(ctx, msg) do { _mrlogctxid(ctx); MR_WRITE1(" " msg "\n"); } while(0)
#else
#define TRACEMSG(msg)
#define TRACEMSGCTX(ctx, msg)
#endif

// trace messages to debug crypto data
#if MR_TRACE_DATA
#define TRACEDATA(msg, data, amt) do { MR_WRITE1(message " "); _mrloghex(data, amt); MR_WRITE1("\n"); } while(0)
#else
#define TRACEDATA(msg, data, amt)
#endif
