#include "aes.h"
#include "focalors.h"
#include <cstddef>
#include <vector>
using focalors::byte;
using focalors::word;
using std::vector;

#ifdef DEBUG
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
using std::cin;
using std::cout;
using std::endl;
using std::string;
std::string hex_to_binary_string(const std::string &hex)
{
    std::stringstream ss;
    for (size_t i = 0; i < hex.size(); ++i)
    {
        unsigned int n;
        std::stringstream(hex.substr(i, 1)) >> std::hex >> n;
        ss << std::bitset<4>(n);
    }
    return ss.str();
}
std::string binary_to_hex_string(const std::string &binary)
{
    std::stringstream ss;
    for (size_t i = 0; i < binary.size(); i += 4)
    {
        std::bitset<4> b(binary.substr(i, 4));
        ss << std::hex << b.to_ulong();
    }
    return ss.str();
}
#endif

namespace aes
{
template <size_t N> void bitset2vectorword(vector<word> &v, const focalors::reverse_bitset<N> &b)
{
    for (size_t i = 0; i < v.size(); i++)
    {
        focalors::reverse_bitset<32> temp;
        for (size_t j = 0; j < 32; j++)
        {
            temp[j] = b[i * 32 + j];
        }
        v[i] = temp;
    }
}
template <size_t N> void vectorword2bitset(focalors::reverse_bitset<N> &b, const vector<word> &v)
{
    for (size_t i = 0; i < v.size(); i++)
    {
        focalors::reverse_bitset<32> temp;
        temp = v[i];
        for (size_t j = 0; j < 32; j++)
        {
            b[i * 32 + j] = temp[j];
        }
    }
}
word rotl(word w)
{
    return (w << 8) | (w >> 24);
}
byte sbox(byte b)
{
    byte result(0);
    result = S[b.to_ulong() >> 4][b.to_ulong() & 0xf];
    return result;
}
word sbox(word w)
{
    word result(0);
    for (int i = 0; i < 4; i++)
    {
        result.set_byte(i, sbox(w.get_byte(i)));
    }
    return result;
}
void sbox(vector<word> &state)
{
    for (auto &i : state)
    {
        i = sbox(i);
    }
}
void key_expansion(const vector<word> &cipher_key, vector<word> &w, int nk)
{
    if (nk <= 6)
    {
        for (int i = 0; i < nk; i++)
        {
            w[i] = cipher_key[i];
        }
        for (size_t i = nk; i < w.size(); i++)
        {
            auto temp = w[i - 1];
            if (i % nk == 0)
            {
                temp = sbox(rotl(temp)) ^ RCON.at(i / nk - 1);
            }
            w[i] = w[i - nk] ^ temp;
        }
    }
    else
    {
        for (int i = 0; i < nk; i++)
        {
            w[i] = cipher_key[i];
        }
        for (size_t i = nk; i < w.size(); i++)
        {
            auto temp = w[i - 1];
            if (i % nk == 0)
            {
                temp = sbox(rotl(temp)) ^ RCON.at(i / nk - 1);
            }
            else
            {
                if (i % nk == 4)
                {
                    temp = sbox(temp);
                }
            }
            w[i] = w[i - nk] ^ temp;
        }
    }
}
byte gf_mul(byte a, byte b)
{
    byte result(0);
    for (int i = 0; i < 8; i++)
    {
        if (b[i])
        {
            result ^= a;
        }
        if (a[7])
        {
            a <<= 1;
            a ^= 0x1b;
        }
        else
        {
            a <<= 1;
        }
    }
    return result;
}
void add_round_key(vector<word> &state, const vector<word> &w, int round)
{
    for (size_t i = 0; i < state.size(); i++)
    {
        state[i] ^= w.at(round * state.size() + i);
    }
}
void shift_row(vector<word> &state)
{
    const auto &cx = CX[(state.size() - 4) >> 1];
    for (int i = 0; i < 4; i++)
    {
        vector<byte> temp(cx[i]);
        {
            auto j = state.begin();
            auto k = temp.begin();
            for (; k != temp.end(); j++, k++)
            {
                *k = j->get_byte(i);
            }
        }
        {
            auto j = state.begin();
            for (; j + cx[i] < state.end(); j++)
            {
                j->set_byte(i, (j + cx[i])->get_byte(i));
            }
            for (auto k = temp.begin(); k != temp.end(); j++, k++)
            {
                j->set_byte(i, *k);
            }
        }
    }
}
void mix_column(vector<word> &state)
{
    for (size_t i = 0; i < state.size(); i++)
    {
        vector<byte> temp(4, 0);
        for (int j = 0; j < 4; j++)
        {
            for (int k = 0; k < 4; k++)
            {
                temp[j] ^= gf_mul(C[j][k], state[i].get_byte(k));
            }
        }
        for (int j = 0; j < 4; j++)
        {
            state[i].set_byte(j, temp[j]);
        }
    }
}
void round(vector<word> &state, const vector<word> &w, int round)
{
    sbox(state);
    shift_row(state);
    mix_column(state);
    add_round_key(state, w, round);
}
void final_round(vector<word> &state, const vector<word> &w, int round)
{
    sbox(state);
    shift_row(state);
    add_round_key(state, w, round);
}
void inv_mix_column(word &w)
{
    vector<byte> temp(4, 0);
    for (int j = 0; j < 4; j++)
    {
        for (int k = 0; k < 4; k++)
        {
            temp[j] ^= gf_mul(INV_C[j][k], w.get_byte(k));
        }
    }
    for (int j = 0; j < 4; j++)
    {
        w.set_byte(j, temp[j]);
    }
}
void inv_mix_column(vector<word> &state)
{
    for (auto &i : state)
    {
        inv_mix_column(i);
    }
}
void inv_key_expansion(const vector<word> &cipher_key, vector<word> &w, int nk, int nb)
{
    key_expansion(cipher_key, w, nk);
    for (auto i = w.begin() + nb; i + nb < w.end(); i++)
    {
        inv_mix_column(*i);
    }
}
void inv_shift_row(vector<word> &state)
{
    const auto &cx = CX[(state.size() - 4) >> 1];
    for (int i = 0; i < 4; i++)
    {
        vector<byte> temp(cx[i]);
        {
            auto j = state.rbegin();
            auto k = temp.begin();
            for (; k != temp.end(); j++, k++)
            {
                *k = j->get_byte(i);
            }
        }
        {
            auto j = state.rbegin();
            for (; j + cx[i] < state.rend(); j++)
            {
                j->set_byte(i, (j + cx[i])->get_byte(i));
            }
            for (auto k = temp.begin(); k != temp.end(); j++, k++)
            {
                j->set_byte(i, *k);
            }
        }
    }
}
byte inv_sbox(byte b)
{
    byte result(0);
    result = INV_S[b.to_ulong() >> 4][b.to_ulong() & 0xf];
    return result;
}
word inv_sbox(word w)
{
    word result(0);
    for (int i = 0; i < 4; i++)
    {
        result.set_byte(i, inv_sbox(w.get_byte(i)));
    }
    return result;
}
void inv_sbox(vector<word> &state)
{
    for (auto &i : state)
    {
        i = inv_sbox(i);
    }
}
void inv_round(vector<word> &state, const vector<word> &w, int round)
{
    inv_sbox(state);
    inv_shift_row(state);
    inv_mix_column(state);
    add_round_key(state, w, round);
}
void inv_final_round(vector<word> &state, const vector<word> &w, int round)
{
    inv_sbox(state);
    inv_shift_row(state);
    add_round_key(state, w, round);
}
} // namespace aes

namespace focalors
{
using namespace aes;
template <std::size_t BN, std::size_t KN>
void aes_encrypt(focalors::reverse_bitset<BN> &ciphertext, const focalors::reverse_bitset<BN> &plaintext, const focalors::reverse_bitset<KN> &key)
{
    int nb = NB.at(plaintext.size());
    int nk = NK.at(key.size());
    int nr = NR[(nk - 4) >> 1][(nb - 4) >> 1];
    vector<focalors::word> w(nb * (nr + 1));
    vector<focalors::word> cipher_key(nk);
    bitset2vectorword(cipher_key, key);
    key_expansion(cipher_key, w, nk);
    vector<focalors::word> state(nb);
    bitset2vectorword(state, plaintext);
    add_round_key(state, w, 0);
    for (int i = 1; i < nr; i++)
    {
        round(state, w, i);
    }
    final_round(state, w, nr);
    vectorword2bitset(ciphertext, state);
}
template <std::size_t BN, std::size_t KN>
void aes_decrypt(focalors::reverse_bitset<BN> &plaintext, const focalors::reverse_bitset<BN> &ciphertext, const focalors::reverse_bitset<KN> &key)
{
    int nb = NB.at(ciphertext.size());
    int nk = NK.at(key.size());
    int nr = NR[(nk - 4) >> 1][(nb - 4) >> 1];
    vector<focalors::word> w(nb * (nr + 1));
    vector<focalors::word> cipher_key(nk);
    bitset2vectorword(cipher_key, key);
    inv_key_expansion(cipher_key, w, nk, nb);
    vector<focalors::word> state(nb);
    bitset2vectorword(state, ciphertext);
    add_round_key(state, w, nr);
    for (int i = nr - 1; i >= 1; i--)
    {
        inv_round(state, w, i);
    }
    inv_final_round(state, w, 0);
    vectorword2bitset(plaintext, state);
}

template void aes_encrypt<128, 128>(focalors::reverse_bitset<128> &ciphertext, const focalors::reverse_bitset<128> &plaintext,
                                    const focalors::reverse_bitset<128> &key);
template void aes_encrypt<128, 192>(focalors::reverse_bitset<128> &ciphertext, const focalors::reverse_bitset<128> &plaintext,
                                    const focalors::reverse_bitset<192> &key);
template void aes_encrypt<128, 256>(focalors::reverse_bitset<128> &ciphertext, const focalors::reverse_bitset<128> &plaintext,
                                    const focalors::reverse_bitset<256> &key);
template void aes_decrypt<128, 128>(focalors::reverse_bitset<128> &plaintext, const focalors::reverse_bitset<128> &cihpertext,
                                    const focalors::reverse_bitset<128> &key);
template void aes_decrypt<128, 192>(focalors::reverse_bitset<128> &plaintext, const focalors::reverse_bitset<128> &ciphertext,
                                    const focalors::reverse_bitset<192> &key);
template void aes_decrypt<128, 256>(focalors::reverse_bitset<128> &plaintext, const focalors::reverse_bitset<128> &ciphertext,
                                    const focalors::reverse_bitset<256> &key);
} // namespace focalors

#ifdef DEBUG
int main()
{
    cout << "AES-128加密解密" << endl;
    cout << "[1]加密 [2]解密" << endl;
    cout << "请输入操作序号" << endl;
    int choice;
    cin >> choice;
    switch (choice)
    {
    case 1: {
        string plaintext_str, key_str;
        cout << "请输入明文(16进制)：";
        cin >> plaintext_str;
        cout << "请输入密钥(16进制)：";
        cin >> key_str;
        if (plaintext_str.size() != 32 || key_str.size() != 32)
        {
            throw std::invalid_argument("输入长度错误");
        }
        focalors::bitset<128> plaintext(hex_to_binary_string(plaintext_str));
        focalors::bitset<128> key(hex_to_binary_string(key_str));
        focalors::bitset<128> ciphertext;
        focalors::aes_encrypt(ciphertext, plaintext, key);
        cout << "明文：" << plaintext_str << endl;
        cout << "密钥：" << key_str << endl;
        cout << "密文：" << binary_to_hex_string(ciphertext.to_string()) << endl;
        break;
    }
    case 2: {
        string ciphertext_str, key_str;
        cout << "请输入密文(16进制)：";
        cin >> ciphertext_str;
        cout << "请输入密钥(16进制)：";
        cin >> key_str;
        if (ciphertext_str.size() != 32 || key_str.size() != 32)
        {
            throw std::invalid_argument("输入长度错误");
        }
        focalors::bitset<128> ciphertext(hex_to_binary_string(ciphertext_str));
        focalors::bitset<128> key(hex_to_binary_string(key_str));
        focalors::bitset<128> plaintext;
        focalors::aes_decrypt(plaintext, ciphertext, key);
        cout << "密文：" << ciphertext_str << endl;
        cout << "密钥：" << key_str << endl;
        cout << "明文：" << binary_to_hex_string(plaintext.to_string()) << endl;
        break;
    }
    default:
        throw std::invalid_argument("无效操作序号");
        break;
    }
    return 0;
}
#endif