// echo -n "" | xxd -r -p | openssl enc -aes-128-ecb -K "" -nosalt -nopad | xxd -p
#include "focalors.h"
#include "test.h"
#include "gtest/gtest.h"
using namespace focalors;
using namespace std;

// clang-format off
const vector<test_case> test_cases = {
{hex_to_bytes("0001000101a198afda78173486153566""0001000101a198afda78173486153566""0001000101a198afda78173486153566"),
    hex_to_bytes("00012001710198aeda79171460153594"),
    hex_to_bytes("6cdd596b8f5642cbd23b47981a65422a""6cdd596b8f5642cbd23b47981a65422a""6cdd596b8f5642cbd23b47981a65422a")},

{hex_to_bytes("9ed1e56b2003827f3872fc0e97395836b4b8e77ed7431d80f81e4e2ab6e910faa7da4d05814c015cd73a2e407430c2b2"),
hex_to_bytes("1df343be0571dbfc611d3ada5f573fff"),
hex_to_bytes("bb2fa49b8c96ffb9fabb1762d451acc200ad293a5f386e554a0123ef8724cef7361c3984f4289bdf5bd2fd8c284b72b3")}
};
// clang-format on

TEST(BlockCipherModeTest, ECB)
{
    for (const auto &i : test_cases)
    {
        auto &plaintext = i.plaintext;
        auto &key = i.key;
        auto &ciphertext = i.ciphertext;
        auto ecb = ECB(key, AES());
        // encrypt
        auto encrypted = ecb.encrypt(plaintext.begin(), plaintext.end());
        EXPECT_EQ(bytes_to_hex(encrypted), bytes_to_hex(ciphertext));

        // decrypt
        auto decrypted = ecb.decrypt(ciphertext.begin(), ciphertext.end());
        EXPECT_EQ(bytes_to_hex(decrypted), bytes_to_hex(plaintext));
    }
}