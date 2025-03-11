//echo -n "input_hex" | xxd -r -p | openssl enc -aes-128-ecb -K "key_hex" -nosalt -nopad | xxd -p
#include "focalors.h"
#include "test.h"
#include "gtest/gtest.h"
using namespace focalors;
using namespace std;

// clang-format off
const vector<test_case> test_cases = {
{{hex_to_bytes("0001000101a198afda78173486153566""0001000101a198afda78173486153566""0001000101a198afda78173486153566"),
    hex_to_bytes("00012001710198aeda79171460153594"),
    hex_to_bytes("6cdd596b8f5642cbd23b47981a65422a""6cdd596b8f5642cbd23b47981a65422a""6cdd596b8f5642cbd23b47981a65422a")}}
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
        EXPECT_STREQ(bytes_to_hex(encrypted).c_str(), bytes_to_hex(ciphertext).c_str());

        // decrypt
        auto decrypted = ecb.decrypt(ciphertext.begin(), ciphertext.end());
        EXPECT_STREQ(bytes_to_hex(decrypted).c_str(), bytes_to_hex(plaintext).c_str());
    }
}