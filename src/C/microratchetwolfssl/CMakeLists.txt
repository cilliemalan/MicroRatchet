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
	../wolfssl/config
	../../../thirdparty/wolfssl)

add_library(microratchetwolfssl STATIC ${SOURCES})
target_link_libraries(microratchetwolfssl wolfssl)
target_compile_definitions(microratchetwolfssl PUBLIC HAVE_CONFIG_H)