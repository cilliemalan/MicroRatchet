# provides crypto functions from wolfssl

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

include_directories(../libmicroratchet)

add_library(microratchetopenssl STATIC ${SOURCES})
# target_link_libraries(microratchetopenssl wolfssl)
# target_compile_definitions(microratchetopenssl PUBLIC HAVE_CONFIG_H)
