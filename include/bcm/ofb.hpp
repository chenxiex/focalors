#pragma once
#ifndef OFB_HPP
#define OFB_HPP
#include "../focalors.hpp"
#include <cstdint>
#include <vector>
namespace focalors
{
// OFB
// public
template <BlockCipher Cipher>
OFB<Cipher>::OFB(Cipher cipher, std::vector<uint8_t> iv) : cipher(std::move(cipher)), iv(std::move(iv))
{
    if (this->iv.size() != this->cipher.block_size())
    {
        throw std::invalid_argument("IV size must be equal to block size.");
    }
}
template <BlockCipher Cipher>
template <ByteInputIt InputIt, std::sentinel_for<InputIt> Sentinel, std::output_iterator<uint8_t> OutputIt>
auto OFB<Cipher>::encrypt(InputIt first, Sentinel last, OutputIt dest) const
{
    const size_t length = std::distance(first, last);
    std::vector<uint8_t> r(iv.begin(), iv.end());
    const auto block_sz = cipher.block_size();
    auto remainning = length;
    for (auto i = first; i < last;)
    {
        cipher.encrypt(r.begin(), r.begin());
        auto step = std::min(remainning, block_sz);
        dest = std::transform(i, std::next(i, step), r.begin(), dest, std::bit_xor<uint8_t>());
        std::advance(i, step);
        remainning -= step;
    }
}
template <BlockCipher Cipher>
template <ByteInputIt InputIt, std::sentinel_for<InputIt> Sentinel, std::output_iterator<uint8_t> OutputIt>
auto OFB<Cipher>::decrypt(InputIt first, Sentinel last, OutputIt dest) const
{
    return encrypt(first, last, dest);
}
} // namespace focalors
#endif // OFB_HPP