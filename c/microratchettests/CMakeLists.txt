# microratchet unit tests
# currently builds against wolfssl

cmake_minimum_required(VERSION 3.0)
include(GoogleTest)

project(microratchettests C CXX ASM)

set(SOURCES
    aes.cpp
    aesctr.cpp
    aeskdf.cpp
    context.cpp
    ecdh.cpp
    ecdhratchet.cpp
    ecdsa.cpp
    initialization.cpp
    pch.cpp
    poly.cpp
    reference.cpp
    rng.cpp
    sha.cpp
    storage.cpp
    support.cpp
    symmetricratchet.cpp)

# microcontrollers don't have linux so we need to provide
# stub syscalls and memory routines
if (EMBEDDED)
    set(SOURCES ${SOURCES} port/syscalls.c)
    set(SOURCES ${SOURCES} port/startup.s)
endif (EMBEDDED)



add_executable(microratchettests ${SOURCES})


if (EMBEDDED)
    target_link_options(microratchettests PUBLIC -T ${CMAKE_CURRENT_SOURCE_DIR}/port/virt.ld)
    target_compile_definitions(microratchettests PUBLIC EMBEDDED)
endif (EMBEDDED)

# with gtest cmake can discover tests automatically
# (but not if we're cross compiling)
if (NOT EMBEDDED AND NOT ARM)
    gtest_discover_tests(microratchettests)
endif ()

include_directories(
    ../libmicroratchet
    ../../thirdparty/googletest/googletest/include
    ../../thirdparty/googletest/googlemock/include
)

target_link_libraries(microratchettests
    microratchet
    wolfssl
    microratchetwolfssl
    gtest
    gmock
    gtest_main)

# we have our own TEST definition that tracks memory allocations
# so we prevent gtest from defining its own
target_compile_definitions(microratchettests PUBLIC GTEST_DONT_DEFINE_TEST)



# generate PCH (but not when cross compiling because it doesn't work for some reason)
if (USE_PCH AND NOT EMBEDDED)
    target_precompile_headers(microratchettests PUBLIC pch.h)
endif (USE_PCH AND NOT EMBEDDED)