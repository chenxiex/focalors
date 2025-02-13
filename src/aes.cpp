#include "aes.h"
#include "focalors.h"
#include "word.h"
#include <cstdint>
#include <iterator>
#include <stdexcept>
#include <vector>
using focalors::word;
using std::vector;

namespace aes
{
std::vector<focalors::word> bytes_to_word(std::vector<uint8_t>::const_iterator first,
                                          std::vector<uint8_t>::const_iterator last)
{
    vector<word> result;
    for (auto i = first; i + 4 <= last; i += 4)
    {
        focalors::word temp(0);
        for (int j = 0; j < 4; j++)
        {
            temp.set_byte(j, *(i + j));
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
void check(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
           const std::vector<uint8_t> &key)
{
    if (std::distance(first, last) != 16)
    {
        throw std::invalid_argument("input size error");
    }
    if (key.size() != 16 && key.size() != 24 && key.size() != 32)
    {
        throw std::invalid_argument("key size error");
    }
}
std::vector<uint8_t> aes_encrypt(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                                 const std::vector<uint8_t> &key)
{
    check(first, last, key);

    auto nb = NB.at(std::distance(first, last) * 8);
    auto nk = NK.at(key.size() * 8);
    auto nr = NR[(nk - 4) >> 1][(nb - 4) >> 1];
    auto cipher_key = bytes_to_word(key.begin(), key.end());
    auto w = key_expansion(cipher_key, nb, nk, nr);
    auto state = bytes_to_word(first, last);
    add_round_key(state, w, 0);
    for (int i = 1; i < nr; i++)
    {
        round(state, w, i);
    }
    final_round(state, w, nr);
    return words_to_bytes(state);
}
std::vector<uint8_t> aes_decrypt(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                                 const std::vector<uint8_t> &key)
{
    check(first, last, key);

    auto nb = NB.at(std::distance(first, last) * 8);
    auto nk = NK.at(key.size() * 8);
    auto nr = NR[(nk - 4) >> 1][(nb - 4) >> 1];
    auto cipher_key = bytes_to_word(key.begin(), key.end());
    auto w = inv_key_expansion(cipher_key, nb, nk, nr);
    auto state = bytes_to_word(first, last);
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
size_t AES::block_size() const noexcept
{
    return 16;
}
std::vector<uint8_t> AES::encrypt(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                                  const std::vector<uint8_t> &key) const
{
    return aes::aes_encrypt(first, last, key);
}
std::vector<uint8_t> AES::decrypt(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                                  const std::vector<uint8_t> &key) const
{
    return aes::aes_decrypt(first, last, key);
}
} // namespace focalors