cmake_minimum_required(VERSION 3.10)
project(focalors)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type")

include_directories(include)

set(SRCS
    src/des.cpp
    src/main.cpp
    src/bcm.cpp
    src/type.cpp
    src/aes.cpp
)

add_executable(focalors ${SRCS})

target_compile_options(focalors PRIVATE -Wall)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(focalors PRIVATE -g)
else()
    target_compile_options(focalors PRIVATE -O2)
endif()