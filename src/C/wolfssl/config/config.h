#pragma once

// the wolfSSL wolfCrypt config file
#define WOLFCRYPT_ONLY
#define USE_FAST_MATH
#define TFM_TIMING_RESISTANT
#define HAVE_ECC
#define HAVE_POLY1305
#define HAVE_COMP_KEY
#define NO_RSA
#define ECC_TIMING_RESISTANT
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_LIB
#define FP_MAX_BITS 1024
#define NO_WOLFSSL_DIR 
#define WOLFSSL_USER_IO
#define SINGLE_THREADED
#define NO_WRITEV

#if defined(__x86_64__) || defined(_M_AMD64)
#define HAVE_INTEL_RDSEED
#define FORCE_FAILURE_RDSEED
#define WOLFSSL_AESNI
#endif
