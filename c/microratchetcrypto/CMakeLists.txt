# provides custom crypto functions with no external dependencies

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

add_library(microratchetcrypto STATIC ${SOURCES})
