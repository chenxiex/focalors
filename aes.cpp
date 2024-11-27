#include "aes.h"
#include "crypt.h"
#include <cstddef>
#include <vector>
using crypt::byte;
using crypt::word;
using std::vector;

#ifdef DEBUG
#include <iostream>
#include <sstream>
using std::cout;
using std::endl;
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
template <size_t N> void bitset2vectorword(vector<word> &v, const crypt::bitset<N> &b)
{
    for (size_t i = 0; i < v.size(); i++)
    {
        crypt::bitset<32> temp;
        for (size_t j = 0; j < 32; j++)
        {
            temp[j] = b[i * 32 + j];
        }
        v[i] = temp;
    }
}
template <size_t N> void vectorword2bitset(crypt::bitset<N> &b, const vector<word> &v)
{
    for (size_t i = 0; i < v.size(); i++)
    {
        crypt::bitset<32> temp;
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

namespace crypt
{
using namespace aes;
template <std::size_t BN, std::size_t KN>
void aes_encrypt(crypt::bitset<BN> &ciphertext, const crypt::bitset<BN> &plaintext, const crypt::bitset<KN> &key)
{
    int nb = NB.at(plaintext.size());
    int nk = NK.at(key.size());
    int nr = NR[(nk - 4) >> 1][(nb - 4) >> 1];
    vector<crypt::word> w(nb * (nr + 1));
    vector<crypt::word> cipher_key(nk);
    bitset2vectorword(cipher_key, key);
    key_expansion(cipher_key, w, nk);
#ifdef DEBUG
    for (auto i : w)
    {
        cout << binary_to_hex_string(i.to_string()) << endl;
    }
#endif
    vector<crypt::word> state(nb);
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
void aes_decrypt(crypt::bitset<BN> &plaintext, const crypt::bitset<BN> &ciphertext, const crypt::bitset<KN> &key)
{
    int nb = NB.at(ciphertext.size());
    int nk = NK.at(key.size());
    int nr = NR[(nk - 4) >> 1][(nb - 4) >> 1];
    vector<crypt::word> w(nb * (nr + 1));
    vector<crypt::word> cipher_key(nk);
    bitset2vectorword(cipher_key, key);
    inv_key_expansion(cipher_key, w, nk, nb);
    vector<crypt::word> state(nb);
    bitset2vectorword(state, ciphertext);
    add_round_key(state, w, nr);
    for (int i = nr - 1; i >= 1; i--)
    {
        inv_round(state, w, i);
    }
    inv_final_round(state, w, 0);
    vectorword2bitset(plaintext, state);
}

template void aes_encrypt<128, 128>(crypt::bitset<128> &ciphertext, const crypt::bitset<128> &plaintext,
                                    const crypt::bitset<128> &key);
template void aes_encrypt<128, 192>(crypt::bitset<128> &ciphertext, const crypt::bitset<128> &plaintext,
                                    const crypt::bitset<192> &key);
template void aes_encrypt<128, 256>(crypt::bitset<128> &ciphertext, const crypt::bitset<128> &plaintext,
                                    const crypt::bitset<256> &key);
template void aes_decrypt<128, 128>(crypt::bitset<128> &plaintext, const crypt::bitset<128> &cihpertext,
                                    const crypt::bitset<128> &key);
template void aes_decrypt<128, 192>(crypt::bitset<128> &plaintext, const crypt::bitset<128> &ciphertext,
                                    const crypt::bitset<192> &key);
template void aes_decrypt<128, 256>(crypt::bitset<128> &plaintext, const crypt::bitset<128> &ciphertext,
                                    const crypt::bitset<256> &key);
} // namespace crypt

#ifdef DEBUG
int main()
{
    crypt::bitset<128> plaintext(hex_to_binary_string("0001000101a198afda78173486153566"));
    crypt::bitset<256> key(hex_to_binary_string("00012001710198aeda7917146015359400012001710198aeda79171460153594"));
    crypt::bitset<128> ciphertext;
    crypt::aes_encrypt(ciphertext, plaintext, key);
    crypt::bitset<128> decrypted;
    crypt::aes_decrypt(decrypted, ciphertext, key);
    // std::cout << binary_to_hex_string(ciphertext.to_string());
    // std::cout << std::endl;
    // std::cout << binary_to_hex_string(decrypted.to_string());
    // std::cout<<crypt::word("00000001000000100000001100000100").get_byte(0);
}
#endif