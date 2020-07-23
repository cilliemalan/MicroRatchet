cmake_minimum_required(VERSION 3.0)

# options
option(DEBUG "include debug logging (probably insecure)" OFF)
option(TRACE "include diagnostic logging (insecure)" OFF)
option(TRACEDATA "include diagnostic logging on security parameters (extremely insecure)" OFF)
option(TEST_CHECK_MEMORY "with tests, track allocations and frees to check for memory leaks" OFF)
option(TEST_TRACE_MEMORY "with tests, print all allocations and frees to the console" OFF)
option(BUILD_TESTS "build tests" ON)
set(TARGET "host" CACHE STRING "Which environment to target. Defaults to host system")
set_property(CACHE TARGET PROPERTY STRINGS host arm_lm3s6965evb)

# embedded stuff
if (${TARGET} STREQUAL "arm_lm3s6965evb")
    set(EMBEDDED true)
endif()

if (EMBEDDED)
    set(CMAKE_SYSTEM_NAME Generic)
    set(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
    set(CMAKE_HAVE_LIBC_PTHREAD "")
endif(EMBEDDED)

# policies
if (POLICY CMP0077)
  cmake_policy(SET CMP0077 NEW)
endif()
if (POLICY CMP0091)
  cmake_policy(SET CMP0091 NEW)
endif()
if (POLICY CMP0054)
  cmake_policy(SET CMP0054 NEW)
endif()

# project
project(microratchet)

# embedded stuff
if (EMBEDDED)
    add_compile_definitions(MR_EMBEDDED)
endif(EMBEDDED)

if (${TARGET} STREQUAL "arm_lm3s6965evb")
    message("targetting LM3S6965EVB")
    set(ARM true)
    add_compile_definitions(__CORTEX_M=3)
    add_compile_definitions(LM3S6965EVB)
    set(ARM_CORTEX 3)
    set(LINKER_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/port/lm3s6965evb.ld)
    set(CFLAGS "${CFLAGS} -mthumb -mcpu=cortex-m3")
    set(EMBEDDED_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/port/armcortex.cpp)
endif()

# compiler stuff
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS_DEBUG "-g -Og -DDEBUG")
    set(CMAKE_C_FLAGS_DEBUG "-g -Og -DDEBUG")
endif()
if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    set(CXXFLAGS "${CXXFLAGS} /EHsc")
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreaded         "")
    set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreadedDLL      "")
    set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreadedDebug    "")
    set(CMAKE_ASM_MASM_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY_MultiThreadedDebugDLL "")
endif()

if (ARM)
    set(CMAKE_SYSTEM_PROCESSOR arm)
    if (EMBEDDED)
        set(CFLAGS "${CFLAGS} --specs=nano.specs")
        set(CFLAGS "${CFLAGS} -MMD -MP")
        set(CFLAGS "${CFLAGS} -Wno-psabi")
        set(CFLAGS "${CFLAGS} -fstack-usage -fdata-sections -ffunction-sections")
        set(CXXFLAGS "${CXXFLAGS} -fno-exceptions -fno-rtti -fno-threadsafe-statics -fno-use-cxa-atexit")
        set(LDFLAGS "${LDFLAGS} -Wl,--gc-sections")
        
        # generate map files
        set(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE} -Wl,-Map=<TARGET>.map")
        set(CMAKE_C_LINK_EXECUTABLE "${CMAKE_C_LINK_EXECUTABLE} -Wl,-Map=<TARGET>.map")

        set(TEST_COMPILE_DEFINITIONS -DGTEST_IS_THREADSAFE=0 -DGTEST_OS_WINDOWS=0 -DGTEST_HAS_POSIX_RE=0 -DGTEST_HAS_CLONE=0 -DGTEST_HAS_EXCEPTIONS=0 -DGTEST_HAS_TR1_TUPLE=0 -DGTEST_HAS_STREAM_REDIRECTION=0 -DGTEST_HAS_RTTI=0 -DGTEST_OS_NONE=1)
    endif(EMBEDDED)
endif(ARM)

# c++17 and C11
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

# apply compile options
set(CMAKE_CXX_FLAGS "${CXXFLAGS} ${CFLAGS}")
set(CMAKE_C_FLAGS "${CFLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "${LDFLAGS}")
set(CMAKE_MODULE_LINKER_FLAGS "${LDFLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${LDFLAGS}")

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
option (ENABLE_TESTING OFF)
option (INSTALL_MBEDTLS_HEADERS OFF)
add_subdirectory(thirdparty/mbed-crypto)
add_subdirectory(c/microratchetmbed)
target_compile_definitions(mbedcrypto PUBLIC "MBEDTLS_USER_CONFIG_FILE=<user_config.h>")
target_include_directories(mbedcrypto PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/c/microratchetmbed/config>)

# openssl
if (NOT EMBEDDED)
    add_subdirectory(c/microratchetopenssl)
endif()

# custom
# add_subdirectory(c/microratchetcrypto)


# if tests are to be built, include these
if (BUILD_TESTS)
    if (NOT EMBEDDED)
        enable_testing()
    endif()

    set(INSTALL_GTEST OFF CACHE BOOL "disable googletest installation")
	set(gtest_force_shared_crt ON)
    add_subdirectory(c/microratchettests)
    add_subdirectory(thirdparty/googletest)

    target_compile_definitions(gmock PUBLIC ${TEST_COMPILE_DEFINITIONS})
    target_compile_definitions(gtest PUBLIC ${TEST_COMPILE_DEFINITIONS})
    target_compile_definitions(gtest_main PUBLIC ${TEST_COMPILE_DEFINITIONS})
endif (BUILD_TESTS)
