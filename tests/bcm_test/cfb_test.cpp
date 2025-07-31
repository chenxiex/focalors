// echo -n "" | xxd -r -p | openssl enc -aes-128-cfb -K "" -nosalt -nopad -iv "" | xxd -p
#include "focalors.hpp"
#include "utils.h"
#include "test.h"
#include "gtest/gtest.h"
using namespace focalors;
using namespace std;

// clang-format off
const vector<test_case> test_cases = {
{hex_to_bytes("000000000000000000000000000000000000000000000000000000000000000000"),
hex_to_bytes("00012001710198aeda79171460153594"),
hex_to_bytes("6cdd596b8f5642cbd23b47981a65422ae447dd3d0b3cd81e087944b60f57e69883"),
hex_to_bytes("0001000101a198afda78173486153566")},

{hex_to_bytes("2e4f5d7d9b00dff25ced3e1fdaa9dff565c3d6cbfcc61e3ea88bcae9f537892f69fcab"),
hex_to_bytes("942aafb742ad79e83c81bc22b1993f80"),
hex_to_bytes("267909091a03f696536864d4644e9be07f584b4f5146f9fa9d5939805c8161bcaeca66"),
hex_to_bytes("833d0c6c7a9aba05ed3fb7cb07d2c6f5"),
}
};
// clang-format on

TEST(BlockCipherModeTest, AESCFB)
{
    for (const auto &i : test_cases)
    {
        auto &plaintext = i.plaintext;
        auto &key = i.key;
        auto &ciphertext = i.ciphertext;
        auto &iv = i.iv;
        AES aes;
        CFB cfb(key, aes, iv);
        // encrypt
        auto encrypted = cfb.encrypt(plaintext.begin(), plaintext.end());
        EXPECT_EQ(bytes_to_hex(encrypted), bytes_to_hex(ciphertext));

        // decrypt
        auto decrypted = cfb.decrypt(ciphertext.begin(), ciphertext.end());
        EXPECT_EQ(bytes_to_hex(decrypted), bytes_to_hex(plaintext));
    }
}