# main microratchet library files

cmake_minimum_required(VERSION 3.0)

project(libmicroratchet)

set(SOURCES
    aesctr.c
    context_state.c
    context.c
    internal.c
    kdf.c
    pch.c
    ratchet.c)

add_library(microratchet STATIC ${SOURCES})