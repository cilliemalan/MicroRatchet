# provides crypto functions from mbed crypto

cmake_minimum_required(VERSION 3.0)

set(SOURCES
	aes.c
	ecc_common.c
	ecdh.c
	ecdsa.c
	pch.c
	poly.c
	rng.c
	sha.c)

include_directories(
	../libmicroratchet
	../../thirdparty/mbed-crypto/include)

add_library(microratchetmbed STATIC ${SOURCES})
target_link_libraries(microratchetmbed mbedcrypto)

if (EMBEDDED)
	target_compile_definitions(microratchetmbed PUBLIC MR_EMBEDDED)
endif()


