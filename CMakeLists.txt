cmake_minimum_required(VERSION 3.0)

# add PCH option if version is high enough
if (DEFINED CMAKE_VERSION AND NOT "${CMAKE_VERSION}" VERSION_LESS "3.16.0")
    option(USE_PCH "Generate and use precompiled headers" ON)
endif()

# options
option(DEBUG "Produce a debug build" OFF)
option(TRACE "include diagnostic logging (INSECURE)" OFF)
option(BUILD_TESTS "build tests" ON)
option(ARM_CORTEX "Build for arm cortex targets. CC and CXX must already be set." OFF)

# arm cortex support. Build like this
# CC=arm-none-eabi-gcc CXX=arm-none-eabi-g++ cmake -DARM_CORTEX=ON <sourcedir>
if (ARM_CORTEX)
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
    set(CMAKE_SYSTEM_NAME Generic)
    set(CMAKE_SYSTEM_PROCESSOR arm)
    set(CMAKE_HAVE_LIBC_PTHREAD "")
    add_definitions(-DARMCORTEX)
    add_definitions(-DGTEST_IS_THREADSAFE=0)
    add_definitions(-DGTEST_OS_WINDOWS=0)
    add_definitions(-DGTEST_HAS_POSIX_RE=0 -DGTEST_HAS_CLONE=0 -DGTEST_HAS_EXCEPTIONS=0 -DGTEST_HAS_TR1_TUPLE=0 -DGTEST_HAS_STREAM_REDIRECTION=0 -DGTEST_HAS_RTTI=0)
    add_definitions(-DGTEST_OS_NONE=1)
    add_compile_options(-fno-exceptions)
    set(gtest_disable_pthreads ON CACHE BOOL "disable googletest pthreads")
endif(ARM_CORTEX)


# project
project(microratchet)

# enable all warnings globally
add_compile_options(-Wall)

# debug and release options
if (DEBUG)
    add_definitions(-DDEBUG)
    add_compile_options(-g0 -O0)
else ()
    add_compile_options(-O2)
    add_definitions(-D_FORTIFY_SOURCE=2)
endif (DEBUG)

# trace precompiler defs
if (TRACE)
    add_definitions(-DTRACE)
endif (TRACE)

# set output dirs to sensible paths
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Stuff to build
add_subdirectory(src/C/libmicroratchet)
add_subdirectory(src/C/microratchetwolfssl)
add_subdirectory(src/C/wolfssl)

# if tests are to be built, include these
if (BUILD_TESTS)
    enable_testing()
    set(INSTALL_GTEST OFF CACHE BOOL "disable googletest installation")
    add_subdirectory(src/C/microratchettests)
    add_subdirectory(thirdparty/googletest)
endif (BUILD_TESTS)
