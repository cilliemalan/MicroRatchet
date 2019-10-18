cmake_minimum_required(VERSION 3.0)

project(microratchet)


set(INSTALL_GTEST OFF CACHE BOOL "disable googletest installation")


add_subdirectory(src/C)
add_subdirectory(thirdparty/googletest)
