cmake_minimum_required(VERSION 3.0)

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

add_executable(microratchettests ${SOURCES})


include_directories(
    ../libmicroratchet
    ../../../thirdparty/googletest/googletest/include
    ../../../thirdparty/googletest/googlemock/include
)

target_link_libraries(microratchettests
    microratchet
    wolfssl
    microratchetwolfssl
    gtest
    gmock
    gtest_main)

target_compile_definitions(microratchettests PUBLIC GTEST_DONT_DEFINE_TEST)
target_compile_options(microratchettests PUBLIC -Werror)

if (USE_PCH)
    target_precompile_headers(microratchettests PUBLIC pch.h)
endif (USE_PCH)