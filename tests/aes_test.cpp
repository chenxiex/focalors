#include "focalors.h"
#include <gtest/gtest.h>
#include <test.h>

using namespace std;
using namespace focalors;

// clang-format off
const vector<cases> test_cases = {
{hex_to_bytes("0001000101a198afda78173486153566"),
hex_to_bytes("00012001710198aeda79171460153594"),
hex_to_bytes("6cdd596b8f5642cbd23b47981a65422a")}
};
// clang-format on

TEST(AesTest, Encrypt)
{
    for (const auto &i : test_cases)
    {
        auto &plaintext = i.plaintext;
        auto &key = i.key;
        auto &ciphertext = i.ciphertext;
        auto output = AES().encrypt(plaintext, key);
        EXPECT_STREQ(bytes_to_hex(output).c_str(), bytes_to_hex(ciphertext).c_str());
    }
}

TEST(AesTest, Decrypt)
{
    for (const auto &i : test_cases)
    {
        auto &plaintext = i.plaintext;
        auto &key = i.key;
        auto &ciphertext = i.ciphertext;
        auto output = AES().decrypt(ciphertext, key);
        EXPECT_STREQ(bytes_to_hex(output).c_str(), bytes_to_hex(plaintext).c_str());
    }
}