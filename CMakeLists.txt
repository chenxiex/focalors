cmake_minimum_required(VERSION 3.10)
project(focalors)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type")

include_directories(include src)

set(LIB_SRCS
    src/des.cpp
    src/bcm.cpp
    src/word.cpp
    src/aes.cpp
    src/utils.cpp
)

add_library(focalors ${LIB_SRCS})

#add_executable(furina-cli src/main.cpp)

#target_link_libraries(furina-cli PRIVATE focalors)

#target_compile_options(furina-cli PRIVATE -Wall)
target_compile_options(focalors PRIVATE -Wall)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
#    target_compile_options(furina-cli PRIVATE -g)
    target_compile_options(focalors PRIVATE -g)
else()
#    target_compile_options(furina-cli PRIVATE -O2)
    target_compile_options(focalors PRIVATE -O2)
endif()

option(ENABLE_TESTING "Enable testing" OFF)
if (ENABLE_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()