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
template <std::input_iterator InputIt, std::sentinel_for<InputIt> Sentinel, std::output_iterator<uint8_t> OutputIt>
auto ECB<Cipher>::encrypt(InputIt first, Sentinel last, OutputIt dest) const
{
    ecb(first, last, dest, cipher.block_size(), [this](auto first, auto dest) { return cipher.encrypt(first, dest); });
}
template <BlockCipher Cipher>
template <std::input_iterator InputIt, std::sentinel_for<InputIt> Sentinel, std::output_iterator<uint8_t> OutputIt>
auto ECB<Cipher>::decrypt(InputIt first, Sentinel last, OutputIt dest) const
{
    ecb(first, last, dest, cipher.block_size(), [this](auto first, auto dest) { return cipher.decrypt(first, dest); });
}
// private
template <BlockCipher Cipher>
template <ByteInputIt InputIt, std::sentinel_for<InputIt> Sentinel, std::output_iterator<uint8_t> OutputIt,
          typename Func>
auto ECB<Cipher>::ecb(InputIt first, Sentinel last, OutputIt dest, const size_t block_size, Func cipher_func) const
{
    auto length = std::distance(first, last);
    if (length % block_size != 0)
    {
        throw std::invalid_argument("Input size must be a multiple of block size");
    }
    for (auto i = 0; i + block_size <= length; i += block_size)
    {
        cipher_func(first + i, dest + i);
    }
}
} // namespace focalors
#endif