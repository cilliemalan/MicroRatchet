cmake_minimum_required(VERSION 3.0)

project(microratchet)

if (DEFINED CMAKE_VERSION AND NOT "${CMAKE_VERSION}" VERSION_LESS "3.16.0")
    option(USE_PCH "Generate and use precompiled headers" ON)
endif()

option(DEBUG "Produce a debug build" OFF)
option(TRACE "include diagnostic logging (INSECURE)" OFF)
option(HAVE_SERVER "Include microratchet server support" ON)


add_compile_options(-Wall)

if (DEBUG)
    add_definitions(-DDEBUG)
    add_compile_options(-g0)
endif (DEBUG)
if (TRACE)
    add_definitions(-DTRACE)
endif (TRACE)


set(INSTALL_GTEST OFF CACHE BOOL "disable googletest installation")


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

add_subdirectory(src/C)
add_subdirectory(thirdparty/googletest)
