#include "focalors.h"
#include <gtest/gtest.h>
#include <test.h>
using namespace focalors;
using namespace std;

// clang-format off
vector<cases> des_cases = {
{binary_to_bytes("0011000000110001001100100011001100110100001101010011011000110111"),
binary_to_bytes("0011000100110010001100110011010000110101001101100011011100111000"),
binary_to_bytes("1000101110110100011110100000110011110000101010010110001001101101")}
};
// clang-format on

TEST(DesTest, Encrypt)
{
    for (const auto &i : des_cases)
    {
        auto &plaintext = i.plaintext;
        auto &key = i.key;
        auto &ciphertext = i.ciphertext;
        vector<uint8_t> output = DES().encrypt(plaintext, key);
        EXPECT_STREQ(bytes_to_binary(output).c_str(), bytes_to_binary(ciphertext).c_str());
    }
}

TEST(DesTest, Decrypt)
{
    for (const auto &i : des_cases)
    {
        auto &plaintext = i.plaintext;
        auto &key = i.key;
        auto &ciphertext = i.ciphertext;
        vector<uint8_t> output = DES().decrypt(ciphertext, key);
        EXPECT_STREQ(bytes_to_binary(output).c_str(), bytes_to_binary(plaintext).c_str());
    }
}