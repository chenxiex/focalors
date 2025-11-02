#pragma once
#ifndef CBC_HPP
#define CBC_HPP
#include "../focalors.hpp"
#include <cstdint>
#include <vector>
namespace focalors
{
// CBC
// public
template <BlockCipher Cipher>
CBC<Cipher>::CBC(Cipher cipher, std::vector<uint8_t> iv) : iv(std::move(iv)), cipher(std::move(cipher))
{
    if (this->iv.size() != this->cipher.block_size())
    {
        throw std::invalid_argument("IV size must be equal to block size");
    }
};
template <BlockCipher Cipher>
template <ByteInputIt InputIt, std::sentinel_for<InputIt> Sentinel, std::output_iterator<uint8_t> OutputIt>
void CBC<Cipher>::encrypt(InputIt first, Sentinel last, OutputIt dest) const
{
    auto block_sz = cipher.block_size();
    auto length = std::distance(first, last);
    if (length % block_sz)
    {
        throw std::invalid_argument("Input size must be a multiple of block size");
    }
    for (auto i = 0; i + block_sz <= length; i += block_sz)
    {
        if (i == 0)
        {
            std::transform(first, first + block_sz, iv.begin(), dest, std::bit_xor<uint8_t>());
        }
        else
        {
            std::transform(first + i, first + i + block_sz, dest + i - block_sz, dest + i, std::bit_xor<uint8_t>());
        }
        cipher.encrypt(dest + i, dest + i);
    }
}
template <BlockCipher Cipher>
template <ByteInputIt InputIt, std::sentinel_for<InputIt> Sentinel, std::output_iterator<uint8_t> OutputIt>
void CBC<Cipher>::decrypt(InputIt first, Sentinel last, OutputIt dest) const
{
    using std::vector;
    auto block_sz = cipher.block_size();
    auto length = std::distance(first, last);
    if (length % block_sz)
    {
        throw std::invalid_argument("Input size must be a multiple of block size");
    }
    for (auto i = 0; i + block_sz <= length; i += block_sz)
    {
        cipher.decrypt(first + i, dest + i);
        if (i == 0)
        {
            std::transform(dest, dest + block_sz, iv.begin(), dest, std::bit_xor<uint8_t>());
        }
        else
        {
            std::transform(dest + i, dest + i + block_sz, first + i - block_sz, dest + i, std::bit_xor<uint8_t>());
        }
    }
}
}; // namespace focalors
#endif