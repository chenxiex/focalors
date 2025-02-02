#include "des.h"
#include "focalors.h"
#include "type.h"
#include <array>
#include <cstdint>
#include <stdexcept>
using focalors::reverse_bitset;
using std::array;

namespace des
{
reverse_bitset<28> left_shift(const reverse_bitset<28> &bits, const int &n)
{
    reverse_bitset<28> shifted;
    for (int i = 0; i < 28; i++)
    {
        shifted[i] = bits[(i + KEY_SHL.at(n)) % 28];
    }
    return shifted;
}
reverse_bitset<48> choose(const reverse_bitset<56> &bits)
{
    reverse_bitset<48> chosen;
    for (int i = 0; i < 48; i++)
    {
        chosen[i] = bits[CHOOSE[i] - 1];
    }
    return chosen;
}
void choose1(reverse_bitset<28> &c, reverse_bitset<28> &d, const reverse_bitset<64> &key)
{
    // 选择置换1
    for (int i = 0; i < 28; i++)
    {
        c[i] = key[C0[i] - 1];
        d[i] = key[D0[i] - 1];
    }
}
void choose2(reverse_bitset<28> &c, reverse_bitset<28> &d, reverse_bitset<48> &subkey)
{
    reverse_bitset<56> cd;
    for (int j = 0; j < 28; j++)
    {
        cd[j] = c[j];
        cd[j + 28] = d[j];
    }
    subkey = choose(cd);
}
void generate_subkeys(array<reverse_bitset<48>, 16> &subkeys, const reverse_bitset<64> &key)
{
    reverse_bitset<28> c, d;
    choose1(c, d, key);
    for (int i = 0; i < 16; i++)
    {
        c = left_shift(c, i);
        d = left_shift(d, i);
        choose2(c, d, subkeys[i]);
    }
}
void initial_permutation(reverse_bitset<32> &l, reverse_bitset<32> &r, const reverse_bitset<64> &plaintext)
{
    for (int i = 0; i < 32; i++)
    {
        l[i] = plaintext[IP[i] - 1];
        r[i] = plaintext[IP[i + 32] - 1];
    }
}
reverse_bitset<48> expand(const reverse_bitset<32> &bits)
{
    reverse_bitset<48> expanded;
    for (int i = 0; i < 48; i++)
    {
        expanded[i] = bits[E[i] - 1];
    }
    return expanded;
}
reverse_bitset<32> sbox(const reverse_bitset<48> &bits)
{
    reverse_bitset<32> sboxed;
    for (int i = 0; i < 8; i++)
    {
        int row = bits[i * 6] * 2 + bits[i * 6 + 5];
        int col = bits[i * 6 + 1] * 8 + bits[i * 6 + 2] * 4 + bits[i * 6 + 3] * 2 + bits[i * 6 + 4];
        int val = S[i][row][col];
        for (int j = 0; j < 4; j++)
        {
            sboxed[i * 4 + j] = (val >> (3 - j)) & 1;
        }
    }
    return sboxed;
}
reverse_bitset<32> permutation(const reverse_bitset<32> &bits)
{
    reverse_bitset<32> permuted;
    for (int i = 0; i < 32; i++)
    {
        permuted[i] = bits[P[i] - 1];
    }
    return permuted;
}
void des_encrypt_f(reverse_bitset<32> &l, reverse_bitset<32> &r, const reverse_bitset<48> &subkey)
{
    reverse_bitset<48> expanded = expand(r);
    expanded ^= subkey;
    reverse_bitset<32> sboxed = sbox(expanded);
    reverse_bitset<32> permuted = permutation(sboxed);
    reverse_bitset<32> l1, r1;
    l1 = r;
    r1 = l ^ permuted;
    l = l1;
    r = r1;
}
void ip_1(reverse_bitset<64> &result, const reverse_bitset<64> &bits)
{
    for (int i = 0; i < 64; i++)
    {
        result[i] = bits[IP_1[i] - 1];
    }
}
void des_encrypt(reverse_bitset<64> &ciphertext, const reverse_bitset<64> &plaintext, const reverse_bitset<64> &key)
{
    array<reverse_bitset<48>, 16> subkeys;
    generate_subkeys(subkeys, key);
    reverse_bitset<32> l, r;
    initial_permutation(l, r, plaintext);
    for (int i = 0; i < 16; i++)
    {
        des_encrypt_f(l, r, subkeys[i]);
    }
    reverse_bitset<64> encrypted;
    for (int i = 0; i < 32; i++)
    {
        encrypted[i] = r[i];
        encrypted[i + 32] = l[i];
    }
    ip_1(ciphertext, encrypted);
}
void des_decrypt(reverse_bitset<64> &plaintext, const reverse_bitset<64> &ciphertext, const reverse_bitset<64> &key)
{
    array<reverse_bitset<48>, 16> subkeys;
    generate_subkeys(subkeys, key);
    reverse_bitset<32> l, r;
    initial_permutation(l, r, ciphertext);
    for (auto i = subkeys.rbegin(); i != subkeys.rend(); i++)
    {
        des_encrypt_f(l, r, *i);
    }
    reverse_bitset<64> encrypted;
    for (int i = 0; i < 32; i++)
    {
        encrypted[i] = r[i];
        encrypted[i + 32] = l[i];
    }
    ip_1(plaintext, encrypted);
}
} // namespace des
namespace focalors
{
using namespace std;
vector<uint8_t> des(const vector<uint8_t> &input, const vector<uint8_t> &key, bool encrypt)
{
    if (key.size() != 8)
    {
        throw invalid_argument("Key size must be 8 bytes.");
    }
    if (input.size() != 8)
    {
        throw invalid_argument("Plaintext size must be 8 bytes.");
    }
    reverse_bitset<64> output, input_reverse_bitset(input), key_reverse_bitset(key);
    if (encrypt)
        des::des_encrypt(output, input_reverse_bitset, key_reverse_bitset);
    else
        des::des_decrypt(output, input_reverse_bitset, key_reverse_bitset);
    return output.to_vector();
}
} // namespace focalors