find_package(GTest CONFIG REQUIRED)
include(GoogleTest)

include_directories("include")

set(TEST_SRCS
    "bc_test/des_test.cpp"
    "bc_test/aes_test.cpp"
    "bcm_test/ecb_test.cpp"
    "bcm_test/cbc_test.cpp"
    "bcm_test/ofb_test.cpp"
    "bcm_test/cfb_test.cpp"
    "sc_test/zuc_test.cpp"
)

add_executable("test_exec" "${TEST_SRCS}")
target_link_libraries("test_exec" GTest::gtest_main "focalors")
gtest_discover_tests("test_exec")