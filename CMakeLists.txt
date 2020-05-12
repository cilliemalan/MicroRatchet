cmake_minimum_required(VERSION 3.15)

# add PCH option if version is high enough
if (DEFINED CMAKE_VERSION AND NOT "${CMAKE_VERSION}" VERSION_LESS "3.16.0")
    option(USE_PCH "Generate and use precompiled headers" ON)
endif()

# options
option(TRACE "include diagnostic logging (INSECURE)" OFF)
option(BUILD_TESTS "build tests" ON)
set(TARGET "host" CACHE STRING "Which environment to target. Defaults to host system")
set_property(CACHE TARGET PROPERTY STRINGS host embedded_arm linux_arm)

# policies
if (POLICY CMP0077)
  cmake_policy(SET CMP0077 NEW)
endif (POLICY CMP0077)
if (POLICY CMP0091)
  cmake_policy(SET CMP0091 NEW)
endif (POLICY CMP0091)
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreaded         "")
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreadedDLL      "")
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreadedDebug    "")
set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreadedDebugDLL "")


# CC=arm-none-eabi-gcc CXX=arm-none-eabi-g++ cmake -DTARGET=embedded_arm ..
# qemu-system-arm -cpu cortex-a15 -machine virt -nographic -semihosting -kernel bin/microratchettests
# <NIY> CC=arm-linux-gnueabihf-gcc CXX=arm-linux-gnueabihf-g++ cmake -DTARGET=linux_arm ..
if (${TARGET} STREQUAL "embedded_arm" OR ${TARGET} STREQUAL "linux_arm")
    message("targetting ARM")
    set(ARM true)
endif()
if (${TARGET} STREQUAL "embedded_arm")
    message("targetting EMBEDDED")
    set(EMBEDDED true)
    add_compile_definitions(EMBEDDED)
endif()


if (EMBEDDED)
    SET(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
    set(CMAKE_SYSTEM_NAME Generic)
    set(CMAKE_HAVE_LIBC_PTHREAD "")
endif(EMBEDDED)





# project
project(microratchet)




if (ARM)
    set(CMAKE_SYSTEM_PROCESSOR arm)
    if (EMBEDDED)
        SET(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")
        set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
        set(CMAKE_SYSTEM_NAME Generic)
        set(CMAKE_HAVE_LIBC_PTHREAD "")
        add_definitions(-DEMBEDDED)
        add_definitions(-DGTEST_IS_THREADSAFE=0)
        add_definitions(-DGTEST_OS_WINDOWS=0)
        add_definitions(-DGTEST_HAS_POSIX_RE=0 -DGTEST_HAS_CLONE=0 -DGTEST_HAS_EXCEPTIONS=0 -DGTEST_HAS_TR1_TUPLE=0 -DGTEST_HAS_STREAM_REDIRECTION=0 -DGTEST_HAS_RTTI=0)
        add_definitions(-DGTEST_OS_NONE=1)
        set(gtest_disable_pthreads ON CACHE BOOL "disable googletest pthreads")

        set(CMAKE_CXX_FLAGS "-fno-exceptions")
        add_compile_options(-fno-exceptions)
        add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>)
        add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fno-threadsafe-statics>)
        add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fno-use-cxa-atexit>)
        add_compile_options(-march=armv7-m --specs=nosys.specs)
        add_compile_options(-mthumb)
        add_compile_options(-mno-thumb-interwork)
        add_compile_options(-ffunction-sections -fdata-sections)
        add_compile_options(-Wall -fstack-usage -MMD -MP)

        add_link_options(-Wl,--gc-sections)
        add_link_options(-static)
        add_link_options(--specs=nosys.specs)
        add_link_options(-mthumb)
        add_link_options(-march=armv7-m)
        add_link_options(-Wl,--start-group -lc -lm -lstdc++ -lsupc++ -Wl,--end-group)
    else(EMBEDDED)
    endif(EMBEDDED)
endif(ARM)

# c++ 14
set(CMAKE_CXX_STANDARD 14)

# trace precompiler defs
if (TRACE)
    add_definitions(-DTRACE)
endif (TRACE)

# set output dirs to sensible paths
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Stuff to build
add_subdirectory(c/libmicroratchet)
# wolfssl
add_subdirectory(c/microratchetwolfssl)
add_subdirectory(c/wolfssl)
# mbedtls
option (ENABLE_PROGRAMS OFF)
add_subdirectory(thirdparty/mbed-crypto)
add_subdirectory(c/microratchetmbed)
# openssl
add_subdirectory(c/microratchetopenssl)
# custom
add_subdirectory(c/microratchetcrypto)

# mbed config
target_compile_definitions(mbedcrypto PUBLIC "MBEDTLS_USER_CONFIG_FILE=<user_config.h>")
target_include_directories(mbedcrypto PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/c/microratchetmbed/config>)

# if tests are to be built, include these
if (BUILD_TESTS)
    enable_testing()
    set(INSTALL_GTEST OFF CACHE BOOL "disable googletest installation")
	set(gtest_force_shared_crt ON)
    add_subdirectory(c/microratchettests)
    add_subdirectory(thirdparty/googletest)
endif (BUILD_TESTS)

# visual studio stuff
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# generate list files
if (EMBEDDED)
	set(CMAKE_C_COMPILE_OBJECT "${CMAKE_C_COMPILE_OBJECT} -Wa,-alh=<OBJECT>.lst")
	set(CMAKE_CXX_COMPILE_OBJECT "${CMAKE_C_COMPILE_OBJECT} -Wa,-alh=<OBJECT>.lst")
	set(CMAKE_ASM_COMPILE_OBJECT "${CMAKE_C_COMPILE_OBJECT} -Wa,-alh=<OBJECT>.lst")
endif (EMBEDDED)
