#include "des.h"
#include "focalors.h"
#include "reverse_bitset.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <stdexcept>
#include <tuple>
#include <vector>
using focalors::reverse_bitset;
using std::array;
using std::vector;

namespace des
{
focalors::reverse_bitset<28> left_shift(const focalors::reverse_bitset<28> &bits, const int &n)
{
    reverse_bitset<28> shifted;
    for (int i = 0; i < 28; i++)
    {
        shifted[i] = bits[(i + KEY_SHL.at(n)) % 28];
    }
    return shifted;
}
focalors::reverse_bitset<48> choose(const focalors::reverse_bitset<56> &bits)
{
    reverse_bitset<48> chosen;
    for (int i = 0; i < 48; i++)
    {
        chosen[i] = bits[CHOOSE[i] - 1];
    }
    return chosen;
}
std::pair<focalors::reverse_bitset<28>, focalors::reverse_bitset<28>> choose1(const focalors::reverse_bitset<64> &key)
{
    // 选择置换1
    reverse_bitset<28> c, d;
    for (int i = 0; i < 28; i++)
    {
        c[i] = key[C0[i] - 1];
        d[i] = key[D0[i] - 1];
    }
    return {c, d};
}
focalors::reverse_bitset<48> choose2(const focalors::reverse_bitset<28> &c, const focalors::reverse_bitset<28> &d)
{
    reverse_bitset<48> subkey;
    reverse_bitset<56> cd;
    for (int j = 0; j < 28; j++)
    {
        cd[j] = c[j];
        cd[j + 28] = d[j];
    }
    subkey = choose(cd);
    return subkey;
}
array<reverse_bitset<48>, 16> generate_subkeys(const reverse_bitset<64> &key)
{
    array<reverse_bitset<48>, 16> subkeys;
    reverse_bitset<28> c, d;
    tie(c, d) = choose1(key);
    for (int i = 0; i < 16; i++)
    {
        c = left_shift(c, i);
        d = left_shift(d, i);
        subkeys[i] = choose2(c, d);
    }
    return subkeys;
}
void initial_permutation(focalors::reverse_bitset<32> &l, focalors::reverse_bitset<32> &r,
                         const focalors::reverse_bitset<64> &plaintext)
{
    for (int i = 0; i < 32; i++)
    {
        l[i] = plaintext[IP[i] - 1];
        r[i] = plaintext[IP[i + 32] - 1];
    }
}
focalors::reverse_bitset<48> expand(const focalors::reverse_bitset<32> &bits)
{
    reverse_bitset<48> expanded;
    for (int i = 0; i < 48; i++)
    {
        expanded[i] = bits[E[i] - 1];
    }
    return expanded;
}
focalors::reverse_bitset<32> sbox(const focalors::reverse_bitset<48> &bits)
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
focalors::reverse_bitset<32> permutation(const focalors::reverse_bitset<32> &bits)
{
    reverse_bitset<32> permuted;
    for (int i = 0; i < 32; i++)
    {
        permuted[i] = bits[P[i] - 1];
    }
    return permuted;
}
void des_encrypt_f(focalors::reverse_bitset<32> &l, focalors::reverse_bitset<32> &r,
                   const focalors::reverse_bitset<48> &subkey)
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
focalors::reverse_bitset<64> ip_1(const focalors::reverse_bitset<64> &bits)
{
    reverse_bitset<64> result;
    for (int i = 0; i < 64; i++)
    {
        result[i] = bits[IP_1[i] - 1];
    }
    return result;
}
focalors::reverse_bitset<64> des_encrypt(const focalors::reverse_bitset<64> &plaintext,
                                         const focalors::reverse_bitset<64> &key)
{
    auto subkeys = generate_subkeys(key);
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
    return ip_1(encrypted);
}
focalors::reverse_bitset<64> des_decrypt(const focalors::reverse_bitset<64> &ciphertext,
                                         const focalors::reverse_bitset<64> &key)
{
    auto subkeys = generate_subkeys(key);
    reverse_bitset<32> l, r;
    initial_permutation(l, r, ciphertext);
    std::for_each(subkeys.rbegin(), subkeys.rend(), [&l, &r](reverse_bitset<48> &i) { des_encrypt_f(l, r, i); });
    reverse_bitset<64> encrypted;
    for (int i = 0; i < 32; i++)
    {
        encrypted[i] = r[i];
        encrypted[i + 32] = l[i];
    }
    return ip_1(encrypted);
}
void check(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
           const std::vector<uint8_t> &key)
{
    if (key.size() != 8)
    {
        throw std::invalid_argument("Key size must be 8 bytes.");
    }
    if (std::distance(first, last) != 8)
    {
        throw std::invalid_argument("Input size must be 8 bytes.");
    }
}
} // namespace des

namespace focalors
{
size_t DES::block_size() const noexcept
{
    return 8;
}
vector<uint8_t> DES::encrypt(vector<uint8_t>::const_iterator first, vector<uint8_t>::const_iterator last,
                             const vector<uint8_t> &key) const
{
    des::check(first, last, key);
    reverse_bitset<64> output, input_reverse_bitset(first, last), key_reverse_bitset(key);
    output = des::des_encrypt(input_reverse_bitset, key_reverse_bitset);
    return output.to_vector();
}
vector<uint8_t> DES::decrypt(vector<uint8_t>::const_iterator first, vector<uint8_t>::const_iterator last,
                             const vector<uint8_t> &key) const
{
    des::check(first, last, key);
    reverse_bitset<64> output, input_reverse_bitset(first, last), key_reverse_bitset(key);
    output = des::des_decrypt(input_reverse_bitset, key_reverse_bitset);
    return output.to_vector();
}
} // namespace focalors