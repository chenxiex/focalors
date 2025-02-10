#include "aes.h"
#include "focalors.h"
#include "word.h"
#include <cstdint>
#include <stdexcept>
#include <vector>
using focalors::word;
using std::vector;

namespace aes
{
std::vector<focalors::word> bytes_to_word(const std::vector<uint8_t> &v)
{
    vector<word> result;
    for (size_t i = 0; i < v.size(); i += 4)
    {
        focalors::word temp(0);
        for (int j = 0; j < 4; j++)
        {
            temp.set_byte(j, v.at(i + j));
        }
        result.push_back(temp);
    }
    return result;
}
std::vector<uint8_t> words_to_bytes(const std::vector<focalors::word> &v)
{
    vector<uint8_t> result;
    for (auto i : v)
    {
        for (int j = 0; j < 4; j++)
        {
            result.push_back(i.get_byte(j));
        }
    }
    return result;
}
focalors::word rotl(focalors::word w)
{
    return (w << 8) | (w >> 24);
}
uint8_t sbox(uint8_t b)
{
    return S[b >> 4][b & 0xf];
}
focalors::word sbox(focalors::word w)
{
    word result(0);
    for (int i = 0; i < 4; i++)
    {
        result.set_byte(i, sbox(w.get_byte(i)));
    }
    return result;
}
void sbox(std::vector<focalors::word> &state)
{
    for (auto &i : state)
    {
        i = sbox(i);
    }
}
std::vector<focalors::word> key_expansion(const std::vector<focalors::word> &cipher_key, const int &nb, const int &nk,
                                          const int &nr)
{
    vector<word> w(nb * (nr + 1));
    if (nk <= 6)
    {
        for (int i = 0; i < nk; i++)
        {
            w.at(i) = cipher_key.at(i);
        }
        for (size_t i = nk; i < w.size(); i++)
        {
            auto temp = w.at(i - 1);
            if (i % nk == 0)
            {
                temp = sbox(rotl(temp)) ^ RCON.at(i / nk - 1);
            }
            w.at(i) = w.at(i - nk) ^ temp;
        }
    }
    else
    {
        for (int i = 0; i < nk; i++)
        {
            w.at(i) = cipher_key.at(i);
        }
        for (size_t i = nk; i < w.size(); i++)
        {
            auto temp = w.at(i - 1);
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
            w.at(i) = w.at(i - nk) ^ temp;
        }
    }
    return w;
}
uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t result = 0;
    for (int i = 0; i < 8; i++)
    {
        if (b & (1 << i))
        {
            result ^= a;
        }
        if (a & (1 << 7))
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
void add_round_key(std::vector<focalors::word> &state, const std::vector<focalors::word> &w, const int &round)
{
    for (size_t i = 0; i < state.size(); i++)
    {
        state[i] ^= w.at(round * state.size() + i);
    }
}
void shift_row(std::vector<focalors::word> &state)
{
    const auto &cx = CX[(state.size() - 4) >> 1];
    for (int i = 0; i < 4; i++)
    {
        vector<uint8_t> temp(cx[i]);
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
void mix_column(std::vector<focalors::word> &state)
{
    for (size_t i = 0; i < state.size(); i++)
    {
        vector<uint8_t> temp(4, 0);
        for (int j = 0; j < 4; j++)
        {
            for (int k = 0; k < 4; k++)
            {
                temp.at(j) ^= gf_mul(C[j][k], state.at(i).get_byte(k));
            }
        }
        for (int j = 0; j < 4; j++)
        {
            state.at(i).set_byte(j, temp.at(j));
        }
    }
}
void round(std::vector<focalors::word> &state, const std::vector<focalors::word> &w, const int &round)
{
    sbox(state);
    shift_row(state);
    mix_column(state);
    add_round_key(state, w, round);
}
void final_round(std::vector<focalors::word> &state, const std::vector<focalors::word> &w, const int &round)
{
    sbox(state);
    shift_row(state);
    add_round_key(state, w, round);
}
void inv_mix_column(focalors::word &w)
{
    vector<uint8_t> temp(4, 0);
    for (int j = 0; j < 4; j++)
    {
        for (int k = 0; k < 4; k++)
        {
            temp.at(j) ^= gf_mul(INV_C[j][k], w.get_byte(k));
        }
    }
    for (int j = 0; j < 4; j++)
    {
        w.set_byte(j, temp.at(j));
    }
}
void inv_mix_column(std::vector<focalors::word> &state)
{
    for (auto &i : state)
    {
        inv_mix_column(i);
    }
}
std::vector<focalors::word> inv_key_expansion(const std::vector<focalors::word> &cipher_key, const int &nb,
                                              const int &nk, const int &nr)
{
    vector<word> w = key_expansion(cipher_key, nb, nk, nr);
    for (auto i = w.begin() + nb; i + nb < w.end(); i++)
    {
        inv_mix_column(*i);
    }
    return w;
}
void inv_shift_row(std::vector<focalors::word> &state)
{
    const auto &cx = CX[(state.size() - 4) >> 1];
    for (int i = 0; i < 4; i++)
    {
        vector<uint8_t> temp(cx[i]);
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
uint8_t inv_sbox(uint8_t b)
{
    return INV_S[b >> 4][b & 0xf];
}
focalors::word inv_sbox(focalors::word w)
{
    word result(0);
    for (int i = 0; i < 4; i++)
    {
        result.set_byte(i, inv_sbox(w.get_byte(i)));
    }
    return result;
}
void inv_sbox(std::vector<focalors::word> &state)
{
    for (auto &i : state)
    {
        i = inv_sbox(i);
    }
}
void inv_round(std::vector<focalors::word> &state, const std::vector<focalors::word> &w, const int &round)
{
    inv_sbox(state);
    inv_shift_row(state);
    inv_mix_column(state);
    add_round_key(state, w, round);
}
void inv_final_round(std::vector<focalors::word> &state, const std::vector<focalors::word> &w, const int &round)
{
    inv_sbox(state);
    inv_shift_row(state);
    add_round_key(state, w, round);
}
std::vector<uint8_t> aes_encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key)
{
    if (plaintext.size() != 16)
    {
        throw std::invalid_argument("input size error");
    }
    if (key.size() != 16 && key.size() != 24 && key.size() != 32)
    {
        throw std::invalid_argument("key size error");
    }

    auto nb = NB.at(plaintext.size() * 8);
    auto nk = NK.at(key.size() * 8);
    auto nr = NR[(nk - 4) >> 1][(nb - 4) >> 1];
    auto cipher_key = bytes_to_word(key);
    auto w = key_expansion(cipher_key, nb, nk, nr);
    auto state = bytes_to_word(plaintext);
    add_round_key(state, w, 0);
    for (int i = 1; i < nr; i++)
    {
        round(state, w, i);
    }
    final_round(state, w, nr);
    return words_to_bytes(state);
}
std::vector<uint8_t> aes_decrypt(const std::vector<uint8_t> &ciphertext, const std::vector<uint8_t> &key)
{
    if (ciphertext.size() != 16)
    {
        throw std::invalid_argument("input size error");
    }
    if (key.size() != 16 && key.size() != 24 && key.size() != 32)
    {
        throw std::invalid_argument("key size error");
    }

    auto nb = NB.at(ciphertext.size() * 8);
    auto nk = NK.at(key.size() * 8);
    auto nr = NR[(nk - 4) >> 1][(nb - 4) >> 1];
    auto cipher_key = bytes_to_word(key);
    auto w = inv_key_expansion(cipher_key, nb, nk, nr);
    auto state = bytes_to_word(ciphertext);
    add_round_key(state, w, nr);
    for (int i = nr - 1; i >= 1; i--)
    {
        inv_round(state, w, i);
    }
    inv_final_round(state, w, 0);
    return words_to_bytes(state);
}
} // namespace aes

namespace focalors
{
using namespace std;
using namespace focalors;
vector<uint8_t> aes(const vector<uint8_t> &input, const vector<uint8_t> &key, bool encrypt)
{
    vector<uint8_t> output;
    if (encrypt)
    {
        output = aes::aes_encrypt(input, key);
    }
    else
    {
        output = aes::aes_decrypt(input, key);
    }
    return output;
}
} // namespace focalors