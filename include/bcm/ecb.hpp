#pragma once
#ifndef ECB_HPP
#define ECB_HPP
#include "../focalors.hpp"
namespace focalors
{
// ECB
// public
template <BlockCipher Cipher> ECB<Cipher>::ECB(Cipher cipher) : cipher(std::move(cipher))
{
}
template <BlockCipher Cipher>
std::vector<uint8_t> ECB<Cipher>::encrypt(std::vector<uint8_t>::const_iterator first,
                                          std::vector<uint8_t>::const_iterator last) const
{
    return ecb(first, last, cipher.block_size(), [this](auto first) { return cipher.encrypt(first); });
}
template <BlockCipher Cipher>
std::vector<uint8_t> ECB<Cipher>::decrypt(std::vector<uint8_t>::const_iterator first,
                                          std::vector<uint8_t>::const_iterator last) const
{
    return ecb(first, last, cipher.block_size(), [this](auto first) { return cipher.decrypt(first); });
}

// private
template <BlockCipher Cipher>
template <typename Func>
std::vector<uint8_t> ECB<Cipher>::ecb(std::vector<uint8_t>::const_iterator first,
                                      std::vector<uint8_t>::const_iterator last, const size_t block_size,
                                      Func cipher_func) const
{
    using std::vector;
    if (std::distance(first, last) % block_size != 0)
    {
        throw std::invalid_argument("Input size must be a multiple of block size");
    }
    auto block_sz = block_size;
    vector<uint8_t> output(std::distance(first, last));
    for (auto i = first; i + block_sz <= last; i += block_sz)
    {
        auto block = cipher_func(i);
        std::move(block.begin(), block.end(), output.begin() + (i - first));
    }
    return output;
}
} // namespace focalors
#endif