# microratchet unit tests

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
    highlevel.cpp
    initialization.cpp
    memcpy.cpp
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


    set(CMAKE_CXX_FLAGS "-fno-exceptions")
    add_definitions(-DEMBEDDED)
    add_definitions(-DGTEST_IS_THREADSAFE=0)
    add_definitions(-DGTEST_OS_WINDOWS=0)
    add_definitions(-DGTEST_HAS_POSIX_RE=0 -DGTEST_HAS_CLONE=0 -DGTEST_HAS_EXCEPTIONS=0 -DGTEST_HAS_TR1_TUPLE=0 -DGTEST_HAS_STREAM_REDIRECTION=0 -DGTEST_HAS_RTTI=0)
    add_definitions(-DGTEST_OS_NONE=1)
    set(gtest_disable_pthreads ON CACHE BOOL "disable googletest pthreads")


    set(SOURCES ${SOURCES} port/syscalls.c)
    set(SOURCES ${SOURCES} port/startup.s)
endif (EMBEDDED)



add_executable(microratchettestswolfssl ${SOURCES})
add_executable(microratchettestmbed ${SOURCES})
add_executable(microratchettestopenssl ${SOURCES})
# add_executable(microratchettescrypto ${SOURCES})


if (EMBEDDED)
    target_link_options(microratchettestswolfssl PUBLIC -T ${CMAKE_CURRENT_SOURCE_DIR}/port/virt.ld)
    target_link_options(microratchettestmbed PUBLIC -T ${CMAKE_CURRENT_SOURCE_DIR}/port/virt.ld)
    # target_link_options(microratchettescrypto PUBLIC -T ${CMAKE_CURRENT_SOURCE_DIR}/port/virt.ld)
    target_compile_definitions(microratchettestswolfssl PUBLIC EMBEDDED)
    target_compile_definitions(microratchettestmbed PUBLIC EMBEDDED)
    # target_compile_definitions(microratchettescrypto PUBLIC EMBEDDED)
endif (EMBEDDED)

# with gtest cmake can discover tests automatically
# (but not if we're cross compiling)
if (NOT EMBEDDED AND NOT ARM)
    gtest_discover_tests(microratchettestswolfssl)
    gtest_discover_tests(microratchettestmbed)
    gtest_discover_tests(microratchettestopenssl)
    # gtest_discover_tests(microratchettescrypto)
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
# target_link_libraries(microratchettescrypto
#     microratchet
#     microratchetcrypto
#     gtest
#     gmock
#     gtest_main)

if (TEST_CHECK_MEMORY)
    target_compile_definitions(microratchettestswolfssl PUBLIC DEBUGMEM)
    target_compile_definitions(microratchettestmbed PUBLIC DEBUGMEM)
    target_compile_definitions(microratchettestopenssl PUBLIC DEBUGMEM)
    # target_compile_definitions(microratchettescrypto PUBLIC DEBUGMEM)
endif()

if (TEST_TRACE_MEMORY)
    target_compile_definitions(microratchettestswolfssl PUBLIC TRACEMEM)
    target_compile_definitions(microratchettestmbed PUBLIC TRACEMEM)
    target_compile_definitions(microratchettestopenssl PUBLIC TRACEMEM)
    # target_compile_definitions(microratchettescrypto PUBLIC TRACEMEM)
endif()

	
target_compile_definitions(microratchettestswolfssl PUBLIC WOLFSSL)
target_compile_definitions(microratchettestmbed PUBLIC MBEDCRYPTO)
target_compile_definitions(microratchettestopenssl PUBLIC OPENSSL)
# target_compile_definitions(microratchettescrypto PUBLIC CUSTOMCRYPTO DOES_NOT_SUPPORT_192)

# we have our own TEST definition that tracks memory allocations
# so we prevent gtest from defining its own
target_compile_definitions(microratchettestswolfssl PUBLIC GTEST_DONT_DEFINE_TEST)
target_compile_definitions(microratchettestmbed PUBLIC GTEST_DONT_DEFINE_TEST)
target_compile_definitions(microratchettestopenssl PUBLIC GTEST_DONT_DEFINE_TEST)
# target_compile_definitions(microratchettescrypto PUBLIC GTEST_DONT_DEFINE_TEST)
