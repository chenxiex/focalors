//echo -n "input_hex" | xxd -r -p | openssl enc -aes-128-ofb -K "key_hex" -nosalt -nopad -iv "z_hex" | xxd -p
#include "focalors.h"
#include "test.h"
#include "gtest/gtest.h"
using namespace focalors;
using namespace std;

// clang-format off
const vector<test_case> test_cases = {
{hex_to_bytes("000000000000000000000000000000000000000000000000000000000000000000"),
hex_to_bytes("00012001710198aeda79171460153594"),
hex_to_bytes("6cdd596b8f5642cbd23b47981a65422ae447dd3d0b3cd81e087944b60f57e69883")}
};
// clang-format on

TEST(BlockCipherModeTest, OFB)
{
    for (const auto &i : test_cases)
    {
        auto &plaintext = i.plaintext;
        auto &key = i.key;
        auto &ciphertext = i.ciphertext;
        auto z = hex_to_bytes("0001000101a198afda78173486153566");
        auto ofb = OFB(key, AES(), z);
        // encrypt
        auto encrypted = ofb.encrypt(plaintext.begin(), plaintext.end());
        EXPECT_STREQ(bytes_to_hex(encrypted).c_str(), bytes_to_hex(ciphertext).c_str());

        // decrypt
        auto decrypted = ofb.decrypt(ciphertext.begin(), ciphertext.end());
        EXPECT_STREQ(bytes_to_hex(decrypted).c_str(), bytes_to_hex(plaintext).c_str());
    }
}