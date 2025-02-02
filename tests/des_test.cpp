#include "focalors.h"
#include <gtest/gtest.h>
using namespace focalors;
using namespace std;

const vector<uint8_t> plaintext = binary_to_bytes("0011000000110001001100100011001100110100001101010011011000110111");
const vector<uint8_t> key = binary_to_bytes("0011000100110010001100110011010000110101001101100011011100111000");
const vector<uint8_t> ciphertext = binary_to_bytes("1000101110110100011110100000110011110000101010010110001001101101");

TEST(DesTest, Encrypt)
{
    auto &input = plaintext;
    vector<uint8_t> output = des(input, key, true);
    EXPECT_STREQ(bytes_to_binary(output).c_str(), bytes_to_binary(ciphertext).c_str());
}

TEST(DesTest, Decrypt)
{
    auto &input = ciphertext;
    vector<uint8_t> output = des(input, key, false);
    EXPECT_STREQ(bytes_to_binary(output).c_str(), bytes_to_binary(plaintext).c_str());
}