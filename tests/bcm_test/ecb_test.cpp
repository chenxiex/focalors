#include "focalors.h"
#include "test.h"
#include "gtest/gtest.h"
using namespace focalors;
using namespace std;

// clang-format off
const vector<test_case> test_cases = {
{hex_to_bytes("0000000000000000""1111111111111111""2222222222222222"),
hex_to_bytes("ffffffffffffffff"),
hex_to_bytes("ffffffffffffffff""eeeeeeeeeeeeeeee""dddddddddddddddd")}
};
// clang-format on

TEST(BlockCipherModeTest, ECB)
{
    for (const auto &i : test_cases)
    {
        auto &plaintext = i.plaintext;
        auto &key = i.key;
        auto &ciphertext = i.ciphertext;
        auto ecb = ECB(key, simple_block_cipher());
        // encrypt
        auto encrypted = ecb.encrypt(plaintext.begin(), plaintext.end());
        EXPECT_STREQ(bytes_to_hex(encrypted).c_str(), bytes_to_hex(ciphertext).c_str());

        // decrypt
        auto decrypted = ecb.decrypt(ciphertext.begin(), ciphertext.end());
        EXPECT_STREQ(bytes_to_hex(decrypted).c_str(), bytes_to_hex(plaintext).c_str());
    }
}