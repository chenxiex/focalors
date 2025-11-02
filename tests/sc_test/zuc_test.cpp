#include "focalors.hpp"
#include "test.hpp"
#include "utils.h"
#include "gtest/gtest.h"
using namespace focalors;
using namespace std;
struct zuc_test_case
{
    const uint32_t count;
    const uint8_t bearer;
    const bool direction;
    const vector<uint8_t> key;
    const vector<uint8_t> plaintext;
    const vector<uint8_t> ciphertext;
};

// clang-format off
const vector<test_case> gen_test_cases = {
{vector<uint8_t>(),
hex_to_bytes("3d4c4be96a82fdaeb58f641db17b455b"),
hex_to_bytes("14f1c2723279c419"),
hex_to_bytes("84319aa8de6915ca1f6bda6bfbd8c766")},
};
const vector<zuc_test_case> enc_test_cases = {
{0x66035492, 
0xf, 
0, 
hex_to_bytes("173d14ba5003731d7a60049470f00a29"), 
hex_to_bytes("6cf65340735552ab0c9752fa6f9025fe0bd675d9005875b2"),
hex_to_bytes("a6c85fc66afb8533aafc2518dfe784940ee1e4b030238cc8")},
};
// clang-format on

TEST(StreamCipherTest, ZUC)
{
    for (const auto &i : gen_test_cases)
    {
        auto &key = i.key;
        auto &ciphertext = i.ciphertext;
        auto &iv = i.iv;
        auto zuc = ZUC(key, iv);
        auto encrypted = vector<uint8_t>();
        while (encrypted.size() < ciphertext.size())
        {
            encrypted.push_back(zuc.generate_keystream_byte());
        }
        EXPECT_EQ(bytes_to_hex(encrypted), bytes_to_hex(ciphertext));
    }
    for (const auto &i : enc_test_cases)
    {
        auto zuc_enc = ZUC_128_EEA3(i.count, i.bearer, i.direction, i.key);
        auto zuc_dec = zuc_enc;
        auto encrypted = vector<uint8_t>(i.plaintext);
        zuc_enc.encrypt(encrypted.begin(), encrypted.end(), encrypted.begin());
        EXPECT_EQ(bytes_to_hex(encrypted), bytes_to_hex(i.ciphertext));

        auto decrypted = vector<uint8_t>(i.ciphertext);
        zuc_dec.decrypt(decrypted.begin(), decrypted.end(), decrypted.begin());
        EXPECT_EQ(bytes_to_hex(decrypted), bytes_to_hex(i.plaintext));
    }
}