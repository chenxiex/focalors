#pragma once
#ifndef AES_HPP
#define AES_HPP
#include "focalors.hpp"
#include "word.hpp"
#include <array>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace focalors
{
// AES
// public
constexpr size_t AES::block_size() const noexcept
{
    return block_size_;
}
AES::AES(const auto &key)
{
    nb_ = NB.at(block_size() * 8);
    set_key(key);
}
void AES::set_key(const auto &key)
{
    nk_ = NK.at(key.size() * 8);
    nr_ = NR[(nk_ - 4) >> 1][(nb_ - 4) >> 1];
    auto cipher_key = focalors::bytes_to_word(key.begin(), key.end());
    w_ = key_expansion(cipher_key);
    inv_w_ = w_;
    std::for_each(inv_w_.begin() + nb_, inv_w_.end() - nb_, [](focalors::word &i) { AES::inv_mix_column(i); });
}
template <ByteIterable InputIt, std::sentinel_for<InputIt> Sentinel>
inline std::vector<uint8_t> AES::encrypt(InputIt first, Sentinel last) const
{
    check(first, last);
    auto state = focalors::bytes_to_word(first, last);
    add_round_key(state, w_, 0);
    for (int i = 1; i < nr_; i++)
    {
        round(state, w_, i);
    }
    final_round(state, w_, nr_);
    return words_to_bytes(state);
}
template <ByteIterable InputIt, std::sentinel_for<InputIt> Sentinel>
inline std::vector<uint8_t> AES::decrypt(InputIt first, Sentinel last) const
{
    check(first, last);
    auto state = focalors::bytes_to_word(first, last);
    add_round_key(state, inv_w_, nr_);
    for (int i = nr_ - 1; i >= 1; i--)
    {
        inv_round(state, inv_w_, i);
    }
    inv_final_round(state, inv_w_, 0);
    return words_to_bytes(state);
}

// private
template <std::input_iterator InputIt, std::sentinel_for<InputIt> Sentinel>
inline void AES::check(InputIt first, Sentinel last) const
{
    if (std::distance(first, last) != block_size())
    {
        throw std::invalid_argument("input size error");
    }
}
} // namespace focalors
#endif // AES_HPP