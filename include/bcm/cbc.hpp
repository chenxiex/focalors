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
std::vector<uint8_t> CBC<Cipher>::encrypt(std::vector<uint8_t>::const_iterator first,
                                          std::vector<uint8_t>::const_iterator last) const
{
    using std::vector;
    auto block_sz = cipher.block_size();
    if (std::distance(first, last) % block_sz)
    {
        throw std::invalid_argument("Input size must be a multiple of block size");
    }
    vector<uint8_t> output(std::distance(first, last));
    for (auto i = first; i + block_sz <= last; i += block_sz)
    {
        auto output_it = output.begin() + (i - first);
        if (i == first)
        {
            std::transform(i, i + block_sz, iv.begin(), output_it, std::bit_xor<uint8_t>());
        }
        else
        {
            std::transform(i, i + block_sz, output_it - block_sz, output_it, std::bit_xor<uint8_t>());
        }
        auto block = cipher.encrypt(output_it);
        std::move(block.begin(), block.end(), output_it);
    }
    return output;
}
template <BlockCipher Cipher>
std::vector<uint8_t> CBC<Cipher>::decrypt(std::vector<uint8_t>::const_iterator first,
                                          std::vector<uint8_t>::const_iterator last) const
{
    using std::vector;
    auto block_sz = cipher.block_size();
    if (std::distance(first, last) % block_sz)
    {
        throw std::invalid_argument("Input size must be a multiple of block size");
    }
    vector<uint8_t> output(std::distance(first, last));
    for (auto i = first; i + block_sz <= last; i += block_sz)
    {
        auto block = cipher.decrypt(i);
        auto output_it = output.begin() + (i - first);
        if (i == first)
        {
            std::transform(block.begin(), block.end(), iv.begin(), output_it, std::bit_xor<uint8_t>());
        }
        else
        {
            std::transform(block.begin(), block.end(), i - block_sz, output_it, std::bit_xor<uint8_t>());
        }
    }
    return output;
}
}; // namespace focalors
#endif