#pragma once
#ifndef CFB_HPP
#define CFB_HPP
#include "../focalors.hpp"
#include <cstdint>
#include <vector>
namespace focalors
{
// CFB
// public
template <BlockCipher Cipher>
CFB<Cipher>::CFB(Cipher cipher, std::vector<uint8_t> iv) : cipher(std::move(cipher)), iv(std::move(iv))
{
    if (this->iv.size() != this->cipher.block_size())
    {
        throw std::invalid_argument("IV size must be equal to block size.");
    }
}
template <BlockCipher Cipher>
template <ByteInputIt InputIt, std::sentinel_for<InputIt> Sentinel, std::output_iterator<uint8_t> OutputIt>
auto CFB<Cipher>::encrypt(InputIt first, Sentinel last, OutputIt dest) const
{
    return process<true>(first, last, dest, iv, cipher);
}
template <BlockCipher Cipher>
template <ByteInputIt InputIt, std::sentinel_for<InputIt> Sentinel, std::output_iterator<uint8_t> OutputIt>
auto CFB<Cipher>::decrypt(InputIt first, Sentinel last, OutputIt dest) const
{
    return process<false>(first, last, dest, iv, cipher);
}
// private
template <BlockCipher Cipher>
template <bool encrypt, ByteInputIt InputIt, std::sentinel_for<InputIt> Sentinel,
          std::output_iterator<uint8_t> OutputIt>
auto CFB<Cipher>::process(InputIt first, Sentinel last, OutputIt dest, const std::vector<uint8_t> &iv,
                          const Cipher &cipher) const
{
    const size_t length = std::distance(first, last);
    std::vector<uint8_t> r(iv.size());
    cipher.encrypt(iv.begin(), r.begin());
    const auto block_sz = cipher.block_size();
    for (auto i = 0; i < length; i += block_sz)
    {
        auto step = std::min(length - i, block_sz);
        if constexpr (encrypt)
        {
            std::transform(first + i, first + i + step, r.begin(), dest + i, std::bit_xor<uint8_t>());
            if (step == block_sz)
            {
                cipher.encrypt(dest + i, r.begin());
            }
        }
        else
        {
            auto e = r;
            if (step == block_sz)
            {
                cipher.encrypt(first + i, r.begin());
            }
            std::transform(first + i, first + i + step, e.begin(), dest + i, std::bit_xor<uint8_t>());
        }
    }
}
} // namespace focalors
#endif