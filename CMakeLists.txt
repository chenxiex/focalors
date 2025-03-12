cmake_minimum_required(VERSION 3.10)
project(focalors)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

option(ENABLE_CLANG_TIDY "Enable clang-tidy" OFF)
if (ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY "clang-tidy")
    if(CLANG_TIDY)
        set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY}")
    endif()
endif()

include_directories(include)

set(LIB_SRCS
    src/des.cpp
    src/word.cpp
    src/aes.cpp
    src/utils.cpp
    src/bcm/ecb.cpp
    src/bcm/cbc.cpp
    src/bcm/ofb.cpp
    src/bcm/cfb.cpp
)

add_library(focalors ${LIB_SRCS})

target_compile_options(focalors PRIVATE -Wall -Wextra)

option(ENABLE_TESTING "Enable testing" OFF)
if (ENABLE_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_subdirectory(debug)
endif()