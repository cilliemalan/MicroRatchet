# builds wolfssl

cmake_minimum_required(VERSION 3.0)

project(wolfssl C ASM)

set(WOLFSSL_BASE_DIR ../../../thirdparty/wolfssl/)
set(WOLFSSL_SRC_DIR ${WOLFSSL_BASE_DIR}wolfcrypt/src/)

set(WOLFSSL_SOURCES_BASE
	aes.c arc4.c asn.c blake2b.c camellia.c chacha.c
	chacha20_poly1305.c cmac.c coding.c curve25519.c
	cpuid.c des3.c dh.c  dsa.c ecc.c ed25519.c error.c
	fe_operations.c ge_low_mem.c ge_operations.c hash.c
	hc128.c hmac.c idea.c integer.c logging.c md2.c
	md4.c md5.c memory.c pkcs7.c pkcs12.c poly1305.c
	pwdbased.c rabbit.c random.c ripemd.c rsa.c
    sha.c sha256.c sha3.c sha512.c signature.c srp.c
	tfm.c wc_encrypt.c wc_port.c wolfmath.c wolfevent.c)

# we have AES_NI on x64 platform
if (NOT ARM AND ${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
	set(WOLFSSL_SOURCES_BASE ${WOLFSSL_SOURCES_BASE} aes_asm.S)
	set_source_files_properties(aes_asm.S PROPERTIES COMPILE_FLAGS "-x assembler-with-cpp")
endif()


# prefix all the sources with the wolfssl path
set(WOLFSSL_SOURCES "")
foreach(f ${WOLFSSL_SOURCES_BASE})
    list(APPEND WOLFSSL_SOURCES "${WOLFSSL_SRC_DIR}${f}")
endforeach(f)

include_directories(
    ${WOLFSSL_BASE_DIR}
    config)

add_library(wolfssl STATIC ${WOLFSSL_SOURCES})

# we have our own config with a load of config settings
target_compile_definitions(wolfssl PUBLIC HAVE_CONFIG_H)
