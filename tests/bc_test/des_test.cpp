#include "focalors.hpp"
#include "utils.h"
#include <gtest/gtest.h>
#include <test.hpp>
using namespace focalors;
using namespace std;

// clang-format off
const vector<test_case> des_cases = {
{binary_to_bytes("0011000000110001001100100011001100110100001101010011011000110111"),
binary_to_bytes("0011000100110010001100110011010000110101001101100011011100111000"),
binary_to_bytes("1000101110110100011110100000110011110000101010010110001001101101")}
};
// clang-format on

TEST(BlockCipherTest, DES)
{
    for (const auto &i : des_cases)
    {
        auto &plaintext = i.plaintext;
        auto &key = i.key;
        auto &ciphertext = i.ciphertext;
        // encrypt
        auto encrypted = vector<uint8_t>(plaintext);
        DES(key).encrypt(encrypted.begin(), encrypted.begin());
        EXPECT_STREQ(bytes_to_binary(encrypted).c_str(), bytes_to_binary(ciphertext).c_str());

        // decrypt
        auto decrypted = vector<uint8_t>(ciphertext);
        DES(key).decrypt(decrypted.begin(), decrypted.begin());
        EXPECT_STREQ(bytes_to_binary(decrypted).c_str(), bytes_to_binary(plaintext).c_str());
    }
}