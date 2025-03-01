#include "focalors.h"
#include "test.h"
#include "gtest/gtest.h"
using namespace focalors;
using namespace std;

// clang-format off
const vector<test_case> test_cases = {
{hex_to_bytes("0000000000000000""1111111111111111""2222222222222222"),
hex_to_bytes("ffffffffffffffff"),
hex_to_bytes("ffffffffffffffff""1111111111111111""cccccccccccccccc")}
};
// clang-format on

TEST(BlockCipherModeTest, CBC)
{
    for (const auto &i : test_cases)
    {
        auto &plaintext = i.plaintext;
        auto &key = i.key;
        auto &ciphertext = i.ciphertext;
        vector<uint8_t> z(simple_block_cipher().block_size(), 0);
        // encrypt
        auto encrypted = CBC().encrypt(plaintext.begin(), plaintext.end(), key, simple_block_cipher(), z);
        EXPECT_STREQ(bytes_to_hex(encrypted).c_str(), bytes_to_hex(ciphertext).c_str());

        // decrypt
        auto decrypted = CBC().decrypt(ciphertext.begin(), ciphertext.end(), key, simple_block_cipher(), z);
        EXPECT_STREQ(bytes_to_hex(decrypted).c_str(), bytes_to_hex(plaintext).c_str());
    }
}