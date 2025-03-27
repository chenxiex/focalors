// echo -n "" | xxd -r -p | openssl enc -aes-128-cbc -K "" -nosalt -nopad -iv "" | xxd -p
#include "focalors.h"
#include "utils.h"
#include "test.h"
#include "gtest/gtest.h"
using namespace focalors;
using namespace std;

// clang-format off
const vector<test_case> test_cases = {
{hex_to_bytes("0001000101a198afda78173486153566""0001000101a198afda78173486153566""0001000101a198afda78173486153566"),
hex_to_bytes("00012001710198aeda79171460153594"),
hex_to_bytes("6cdd596b8f5642cbd23b47981a65422a5d5cd790cb302872881f96da90378f0d347096b0182788d5377f7cbe54a4f9d4"),
hex_to_bytes("00000000000000000000000000000000")},

{hex_to_bytes("adf6e9124b014d5137192bdd089d24a1fb906e6eb2bb1a06eadb2ff2bfddac66428f9fd1dd4f88cfea696c60bd8fd134"),
hex_to_bytes("1a73b67cf315b1c2a916c3b15e4db521"),
hex_to_bytes("33e329850b242d9893308ee17a5e8008024f932d854c472b541a0d9c5e2294693c8a9c242d0689c4cec0a08cd4793493"),
hex_to_bytes("b1ed1ddec26677e3192932d9cf6fdddb"),
}
};
// clang-format on

TEST(BlockCipherModeTest, AESCBC)
{
    for (const auto &i : test_cases)
    {
        auto &plaintext = i.plaintext;
        auto &key = i.key;
        auto &ciphertext = i.ciphertext;
        auto &iv = i.iv;
        AES aes;
        auto cbc = CBC(key, aes, iv);
        // encrypt
        auto encrypted = cbc.encrypt(plaintext.begin(), plaintext.end());
        EXPECT_EQ(bytes_to_hex(encrypted), bytes_to_hex(ciphertext));

        // decrypt
        auto decrypted = cbc.decrypt(ciphertext.begin(), ciphertext.end());
        EXPECT_EQ(bytes_to_hex(decrypted), bytes_to_hex(plaintext));
    }
}