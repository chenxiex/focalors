#include "focalors.hpp"
#include "word.hpp"
#include <algorithm>
#include <cstdint>
#include <iterator>
#include <stdexcept>
#include <vector>
using focalors::word;
using std::vector;

namespace focalors
{
constexpr focalors::word rotl(const focalors::word w, int s) noexcept
{
    return (w << s) | (w >> (w.size() - s));
}
constexpr uint8_t gf_mul(uint8_t a, uint8_t b) noexcept
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
// AES
// private
constexpr uint8_t AES::sbox(uint8_t b) noexcept
{
    return S[b >> 4][b & 0xf];
}
focalors::word AES::sbox(focalors::word w)
{
    word result(0);
    for (int i = 0; i < 4; i++)
    {
        result.set_byte(i, sbox(w.get_byte(i)));
    }
    return result;
}
void AES::sbox(std::vector<focalors::word> &state)
{
    std::for_each(state.begin(), state.end(), [](focalors::word &i) { i = AES::sbox(i); });
}
std::vector<focalors::word> AES::key_expansion(const std::vector<focalors::word> &cipher_key)
{
    vector<word> w(nb_ * (nr_ + 1));
    if (nk_ <= 6)
    {
        for (int i = 0; i < nk_; i++)
        {
            w.at(i) = cipher_key.at(i);
        }
        for (size_t i = nk_; i < w.size(); i++)
        {
            auto temp = w.at(i - 1);
            if (i % nk_ == 0)
            {
                temp = sbox(rotl(temp, 8)) ^ RCON.at(i / nk_ - 1);
            }
            w.at(i) = w.at(i - nk_) ^ temp;
        }
    }
    else
    {
        for (int i = 0; i < nk_; i++)
        {
            w.at(i) = cipher_key.at(i);
        }
        for (size_t i = nk_; i < w.size(); i++)
        {
            auto temp = w.at(i - 1);
            if (i % nk_ == 0)
            {
                temp = sbox(rotl(temp, 8)) ^ RCON.at(i / nk_ - 1);
            }
            else
            {
                if (i % nk_ == 4)
                {
                    temp = sbox(temp);
                }
            }
            w.at(i) = w.at(i - nk_) ^ temp;
        }
    }
    return w;
}
void AES::add_round_key(std::vector<focalors::word> &state, const std::vector<focalors::word> &w,
                        const int &round) noexcept
{
    for (size_t i = 0; i < state.size(); i++)
    {
        state[i] ^= w[round * state.size() + i];
    }
}
void AES::shift_row(std::vector<focalors::word> &state)
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
void AES::mix_column(std::vector<focalors::word> &state)
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
void AES::round(std::vector<focalors::word> &state, const std::vector<focalors::word> &w, const int &round)
{
    sbox(state);
    shift_row(state);
    mix_column(state);
    add_round_key(state, w, round);
}
void AES::final_round(std::vector<focalors::word> &state, const std::vector<focalors::word> &w, const int &round)
{
    sbox(state);
    shift_row(state);
    add_round_key(state, w, round);
}
void AES::inv_mix_column(focalors::word &w)
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
void AES::inv_mix_column(std::vector<focalors::word> &state)
{
    std::for_each(state.begin(), state.end(), [](focalors::word &w) { AES::inv_mix_column(w); });
}
void AES::inv_shift_row(std::vector<focalors::word> &state)
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
constexpr uint8_t AES::inv_sbox(uint8_t b) noexcept
{
    return INV_S[b >> 4][b & 0xf];
}
focalors::word AES::inv_sbox(focalors::word w)
{
    word result(0);
    for (int i = 0; i < 4; i++)
    {
        result.set_byte(i, inv_sbox(w.get_byte(i)));
    }
    return result;
}
void AES::inv_sbox(std::vector<focalors::word> &state)
{
    std::for_each(state.begin(), state.end(), [](focalors::word &i) { i = AES::inv_sbox(i); });
}
void AES::inv_round(std::vector<focalors::word> &state, const std::vector<focalors::word> &w, const int &round)
{
    inv_sbox(state);
    inv_shift_row(state);
    inv_mix_column(state);
    add_round_key(state, w, round);
}
void AES::inv_final_round(std::vector<focalors::word> &state, const std::vector<focalors::word> &w, const int &round)
{
    inv_sbox(state);
    inv_shift_row(state);
    add_round_key(state, w, round);
}
} // namespace focalors