#include "focalors.hpp"
#include "utils.h"
#include <gtest/gtest.h>
#include <test.h>

using namespace std;
using namespace focalors;

// clang-format off
const vector<test_case> test_cases = {
{hex_to_bytes("0001000101a198afda78173486153566"),
hex_to_bytes("00012001710198aeda79171460153594"),
hex_to_bytes("6cdd596b8f5642cbd23b47981a65422a")}
};
// clang-format on

TEST(BlockCipherTest, AES)
{
    for (const auto &i : test_cases)
    {
        auto &plaintext = i.plaintext;
        auto &key = i.key;
        auto &ciphertext = i.ciphertext;
        // encrypt
        auto encrypted = AES().encrypt(plaintext.begin(), plaintext.end(), key);
        EXPECT_EQ(bytes_to_hex(encrypted), bytes_to_hex(ciphertext));

        // decrypt
        auto decrypted = AES().decrypt(ciphertext.begin(), ciphertext.end(), key);
        EXPECT_EQ(bytes_to_hex(decrypted), bytes_to_hex(plaintext));
    }
}