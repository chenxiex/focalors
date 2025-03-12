find_package(GTest CONFIG REQUIRED)
include(GoogleTest)

include_directories(include)

add_executable(des_test des_test.cpp)
target_link_libraries(des_test GTest::gtest_main focalors)
gtest_discover_tests(des_test)

set(TEST_SRCS
    des_test.cpp
    aes_test.cpp
    bcm_test/ecb_test.cpp
    bcm_test/cbc_test.cpp
    bcm_test/ofb_test.cpp
    bcm_test/cfb_test.cpp
)

add_executable(test_exec ${TEST_SRCS})
target_link_libraries(test_exec GTest::gtest_main focalors)
gtest_discover_tests(test_exec)