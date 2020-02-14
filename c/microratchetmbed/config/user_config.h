#pragma once


#ifdef MBEDTLS_HAVE_ASM
#undef MBEDTLS_HAVE_ASM
#endif

#ifdef MBEDTLS_AESNI_C
#undef MBEDTLS_AESNI_C
#endif

#ifdef MBEDTLS_PADLOCK_C
#undef MBEDTLS_PADLOCK_C
#endif


// force 32 bit MPI implementation
#define MBEDTLS_HAVE_INT32



#define MBEDTLS_PLATFORM_MEMORY


#define MBEDTLS_PLATFORM_STD_CALLOC mbedtls_our_calloc
#define MBEDTLS_PLATFORM_STD_FREE mbedtls_our_free


void* MBEDTLS_PLATFORM_STD_CALLOC(size_t a, size_t b);
void MBEDTLS_PLATFORM_STD_FREE(void* pointer);