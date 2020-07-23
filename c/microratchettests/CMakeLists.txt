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

if (EMBEDDED)
    set(SOURCES ${SOURCES}
        port/syscalls.cpp
        port/startup.cpp
        port/interrupts.cpp
        port/system.cpp)
        
    set(gtest_disable_pthreads ON CACHE BOOL "disable googletest pthreads")
endif()

function(add_test_target targetname)

    add_executable(${targetname} ${SOURCES})
    
    # includes
    target_include_directories(${targetname} PUBLIC 
        ../libmicroratchet
        ../../thirdparty/googletest/googletest/include
        ../../thirdparty/googletest/googlemock/include)
    
    # common links
    target_link_libraries(${targetname}
        microratchet
        gtest
        gmock
        gtest_main)
    
    # common compile defs
    target_compile_definitions(${targetname} PUBLIC GTEST_DONT_DEFINE_TEST)
        
    if (TEST_CHECK_MEMORY)
        target_compile_definitions(${targetname} PUBLIC DEBUGMEM)
    endif()
    
    if (TEST_TRACE_MEMORY)
        target_compile_definitions(${targetname} PUBLIC TRACEMEM)
    endif()

    # embedded stuff
    if (EMBEDDED)
        target_compile_definitions(${targetname} PUBLIC -DEMBEDDED)
        target_compile_definitions(${targetname} PUBLIC -DGTEST_IS_THREADSAFE=0)
        target_compile_definitions(${targetname} PUBLIC -DGTEST_OS_WINDOWS=0)
        target_compile_definitions(${targetname} PUBLIC -DGTEST_HAS_POSIX_RE=0 -DGTEST_HAS_CLONE=0 -DGTEST_HAS_EXCEPTIONS=0 -DGTEST_HAS_TR1_TUPLE=0 -DGTEST_HAS_STREAM_REDIRECTION=0 -DGTEST_HAS_RTTI=0)
        target_compile_definitions(${targetname} PUBLIC -DGTEST_OS_NONE=1)
        
        target_link_options(${targetname} PUBLIC -T ${CMAKE_CURRENT_SOURCE_DIR}/port/virt.ld)
    else()
        gtest_discover_tests(${targetname})
    endif()

endfunction()



# the various test targets


# Wolf SSL
add_test_target(microratchettestswolfssl)
target_link_libraries(microratchettestswolfssl
    wolfssl
    microratchetwolfssl)

# ARM Mbed
add_test_target(microratchettestmbed)
target_link_libraries(microratchettestmbed
    mbedcrypto
    microratchetmbed)

# OpenSSL
if (NOT EMBEDDED)
    add_test_target(microratchettestopenssl)
    target_link_libraries(microratchettestopenssl
        microratchetopenssl)
endif()

# Custom (WIP)
if(FALSE)
    add_test_target(microratchettescrypto)
    target_link_libraries(microratchettescrypto
        microratchetcrypto)
endif()