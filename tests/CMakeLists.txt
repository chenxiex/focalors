find_package(GTest CONFIG REQUIRED)
include(GoogleTest)

include_directories(include)

add_library(test_lib test.cpp)

add_executable(des_test des_test.cpp)
target_link_libraries(des_test GTest::gtest_main focalors)
gtest_discover_tests(des_test)

add_executable(aes_test aes_test.cpp)
target_link_libraries(aes_test GTest::gtest_main focalors)
gtest_discover_tests(aes_test)

add_executable(ecb_test bcm_test/ecb_test.cpp)
target_link_libraries(ecb_test GTest::gtest_main focalors test_lib)
gtest_discover_tests(ecb_test)

add_executable(cbc_test bcm_test/cbc_test.cpp)
target_link_libraries(cbc_test GTest::gtest_main focalors test_lib)
gtest_discover_tests(cbc_test)

add_executable(ofb_test bcm_test/ofb_test.cpp)
target_link_libraries(ofb_test GTest::gtest_main focalors test_lib)
gtest_discover_tests(ofb_test)