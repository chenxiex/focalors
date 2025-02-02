cmake_minimum_required(VERSION 3.10)
project(focalors_tests)
enable_testing()

find_package(GTest CONFIG REQUIRED)
include(GoogleTest)

add_executable(des_test des_test.cpp)
target_link_libraries(des_test GTest::gtest_main focalors)
gtest_discover_tests(des_test)

add_executable(aes_test aes_test.cpp)
target_link_libraries(aes_test GTest::gtest_main focalors)
gtest_discover_tests(aes_test)