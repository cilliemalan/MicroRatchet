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
	ecc.cpp
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



add_executable(microratchettestswolfssl ${SOURCES})
add_executable(microratchettestmbed ${SOURCES})
add_executable(microratchettestopenssl ${SOURCES})


if (EMBEDDED)
    target_link_options(microratchettestswolfssl PUBLIC -T ${CMAKE_CURRENT_SOURCE_DIR}/port/virt.ld)
    target_link_options(microratchettestmbed PUBLIC -T ${CMAKE_CURRENT_SOURCE_DIR}/port/virt.ld)
    target_compile_definitions(microratchettestswolfssl PUBLIC EMBEDDED)
    target_compile_definitions(microratchettestmbed PUBLIC EMBEDDED)
endif (EMBEDDED)

# with gtest cmake can discover tests automatically
# (but not if we're cross compiling)
if (NOT EMBEDDED AND NOT ARM)
    gtest_discover_tests(microratchettestswolfssl)
    gtest_discover_tests(microratchettestmbed)
    gtest_discover_tests(microratchettestopenssl)
endif ()

include_directories(
    ../libmicroratchet
    ../../thirdparty/googletest/googletest/include
    ../../thirdparty/googletest/googlemock/include
)

target_link_libraries(microratchettestswolfssl
    microratchet
    wolfssl
    microratchetwolfssl
    gtest
    gmock
    gtest_main)
target_link_libraries(microratchettestmbed
    microratchet
    mbedcrypto
    microratchetmbed
    gtest
    gmock
    gtest_main)
target_link_libraries(microratchettestopenssl
    microratchet
    microratchetopenssl
    gtest
    gmock
    gtest_main)
	
target_compile_definitions(microratchettestswolfssl PUBLIC WOLFSSL)
target_compile_definitions(microratchettestmbed PUBLIC MBEDCRYPTO)
target_compile_definitions(microratchettestopenssl PUBLIC OPENSSL)

# we have our own TEST definition that tracks memory allocations
# so we prevent gtest from defining its own
target_compile_definitions(microratchettestswolfssl PUBLIC GTEST_DONT_DEFINE_TEST)
target_compile_definitions(microratchettestmbed PUBLIC GTEST_DONT_DEFINE_TEST)
target_compile_definitions(microratchettestopenssl PUBLIC GTEST_DONT_DEFINE_TEST)
