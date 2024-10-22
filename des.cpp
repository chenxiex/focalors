#include "des.h"
#include "des_const.h"
#include <array>
using des::bitset;
using std::array;

#ifdef DEBUG
#include <iostream>
using std::cout;
using std::endl;
#endif

namespace des
{
bitset<28> left_shift(const bitset<28> &bits, const int &n)
{
    bitset<28> shifted;
    for (int i = 0; i < 28; i++)
    {
        shifted[i] = bits[(i + KEY_SHL.at(n)) % 28];
    }
    return shifted;
}
bitset<48> choose(const bitset<56> &bits)
{
    bitset<48> chosen;
    for (int i = 0; i < 48; i++)
    {
        chosen[i] = bits[CHOOSE[i] - 1];
    }
    return chosen;
}
void choose1(bitset<28> &c, bitset<28> &d, const bitset<64> &key)
{
    // 选择置换1
    for (int i = 0; i < 28; i++)
    {
        c[i] = key[C0[i] - 1];
        d[i] = key[D0[i] - 1];
    }
}
void choose2(bitset<28> &c, bitset<28> &d, bitset<48> &subkey)
{
    bitset<56> cd;
    for (int j = 0; j < 28; j++)
    {
        cd[j] = c[j];
        cd[j + 28] = d[j];
    }
    subkey = choose(cd);
}
void generate_subkeys(array<bitset<48>, 16> &subkeys, const bitset<64> &key)
{
    bitset<28> c, d;
    choose1(c, d, key);
    for (int i = 0; i < 16; i++)
    {
        c = left_shift(c, i);
        d = left_shift(d, i);
        choose2(c, d, subkeys[i]);
    }
}
void initial_permutation(bitset<32> &l, bitset<32> &r, const bitset<64> &plaintext)
{
    for (int i = 0; i < 32; i++)
    {
        l[i] = plaintext[IP[i] - 1];
        r[i] = plaintext[IP[i + 32] - 1];
    }
}
bitset<48> expand(const bitset<32> &bits)
{
    bitset<48> expanded;
    for (int i = 0; i < 48; i++)
    {
        expanded[i] = bits[E[i] - 1];
    }
    return expanded;
}
bitset<32> sbox(const bitset<48> &bits)
{
    bitset<32> sboxed;
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
bitset<32> permutation(const bitset<32> &bits)
{
    bitset<32> permuted;
    for (int i = 0; i < 32; i++)
    {
        permuted[i] = bits[P[i] - 1];
    }
    return permuted;
}
void des_encrypt_f(bitset<32> &l, bitset<32> &r, const bitset<48> &subkey)
{
    bitset<48> expanded = expand(r);
    expanded ^= subkey;
    bitset<32> sboxed = sbox(expanded);
    bitset<32> permuted = permutation(sboxed);
    bitset<32> l1, r1;
    l1 = r;
    r1 = l ^ permuted;
    l = l1;
    r = r1;
}
void ip_1(bitset<64> &result, const bitset<64> &bits)
{
    for (int i = 0; i < 64; i++)
    {
        result[i] = bits[IP_1[i] - 1];
    }
}
void des_encrypt(bitset<64> &ciphertext, const bitset<64> &plaintext, const bitset<64> &key)
{
    array<bitset<48>, 16> subkeys;
    generate_subkeys(subkeys, key);
    bitset<32> l, r;
    initial_permutation(l, r, plaintext);
    for (int i = 0; i < 16; i++)
    {
        des_encrypt_f(l, r, subkeys[i]);
    }
    bitset<64> encrypted;
    for (int i = 0; i < 32; i++)
    {
        encrypted[i] = r[i];
        encrypted[i + 32] = l[i];
    }
    ip_1(ciphertext, encrypted);
}
void des_decrypt(bitset<64> &plaintext, const bitset<64> &ciphertext, const bitset<64> &key)
{
    array<bitset<48>, 16> subkeys;
    generate_subkeys(subkeys, key);
    bitset<32> l, r;
    initial_permutation(l, r, ciphertext);
    for (int i = 15; i >= 0; i--)
    {
        des_encrypt_f(l, r, subkeys[i]);
    }
    bitset<64> encrypted;
    for (int i = 0; i < 32; i++)
    {
        encrypted[i] = r[i];
        encrypted[i + 32] = l[i];
    }
    ip_1(plaintext, encrypted);
}
} // namespace des

#ifdef DEBUG
int main()
{
    bitset<64> key("0011000100110010001100110011010000110101001101100011011100111000");
    bitset<64> plaintext("0011000000110001001100100011001100110100001101010011011000110111");
    bitset<64> ciphertext;
    des::des_encrypt(ciphertext, plaintext, key);
    cout << "ciphertext: " << ciphertext << endl;
    bitset<64> decrypted;
    des::des_decrypt(decrypted, ciphertext, key);
    cout<< "decrypted: " << decrypted << endl;
    cout<<(decrypted==plaintext)<<endl;
}
#endif