cmake_minimum_required(VERSION 3.0)
include(GoogleTest)


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

if (ARM_CORTEX)
    set(SOURCES ${SOURCES} port/syscalls.c)
endif (ARM_CORTEX)

add_executable(microratchettests ${SOURCES})

if (NOT ARM_CORTEX)
    gtest_discover_tests(microratchettests)
endif ()

include_directories(
    ../libmicroratchet
    ../../../thirdparty/googletest/googletest/include
    ../../../thirdparty/googletest/googlemock/include
)

set(LINKLIBS microratchet
    wolfssl
    microratchetwolfssl
    gtest
    gmock)

if (NOT ARM_CORTEX)
    set(LINKLIBS ${LINKLIBS} gtest_main)
endif ()

target_link_libraries(microratchettests
    microratchet
    wolfssl
    microratchetwolfssl
    gtest
    gmock
    gtest_main)

target_compile_definitions(microratchettests PUBLIC GTEST_DONT_DEFINE_TEST)
target_compile_options(microratchettests PUBLIC -Werror)



if (USE_PCH AND NOT ARM_CORTEX)
    target_precompile_headers(microratchettests PUBLIC pch.h)
endif (USE_PCH AND NOT ARM_CORTEX)