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

find_package(OpenSSL REQUIRED)
target_link_libraries(microratchetopenssl INTERFACE OpenSSL::SSL)
target_link_libraries(microratchetopenssl INTERFACE OpenSSL::Crypto)


target_include_directories(microratchetopenssl PUBLIC "c:\\tools\\openssl\\include")