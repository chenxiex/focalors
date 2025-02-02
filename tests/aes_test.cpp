#include "focalors.h"
#include <gtest/gtest.h>

using namespace std;
using namespace focalors;

const vector<uint8_t> plaintext = hex_to_bytes("0001000101a198afda78173486153566");
const vector<uint8_t> key = hex_to_bytes("00012001710198aeda79171460153594");
const vector<uint8_t> ciphertext = hex_to_bytes("6cdd596b8f5642cbd23b47981a65422a");

TEST(AesTest, Encrypt)
{
    auto output = aes(plaintext, key, true);
    EXPECT_STREQ(bytes_to_hex(output).c_str(), bytes_to_hex(ciphertext).c_str());
}

TEST(AesTest, Decrypt)
{
    auto output = aes(ciphertext, key, false);
    EXPECT_STREQ(bytes_to_hex(output).c_str(), bytes_to_hex(plaintext).c_str());
}