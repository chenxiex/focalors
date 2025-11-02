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
std::vector<uint8_t> CFB<Cipher>::encrypt(std::vector<uint8_t>::const_iterator first,
                                          std::vector<uint8_t>::const_iterator last) const
{
    return process<true>(first, last, iv, cipher);
}
template <BlockCipher Cipher>
std::vector<uint8_t> CFB<Cipher>::decrypt(std::vector<uint8_t>::const_iterator first,
                                          std::vector<uint8_t>::const_iterator last) const
{
    return process<false>(first, last, iv, cipher);
}
// private
template <BlockCipher Cipher>
template <bool encrypt>
std::vector<uint8_t> CFB<Cipher>::process(std::vector<uint8_t>::const_iterator first,
                                          std::vector<uint8_t>::const_iterator last, const std::vector<uint8_t> &iv,
                                          const Cipher &cipher) const
{
    const size_t length = std::distance(first, last);
    std::vector<uint8_t> r(iv.begin(), iv.end());
    std::vector<uint8_t> result(length);
    const auto block_sz = cipher.block_size();
    auto result_it = result.begin();
    auto remainning = length;
    for (auto i = first; i < last;)
    {
        auto step = std::min(remainning, block_sz);
        if constexpr (encrypt)
        {
            r = cipher.encrypt(r.begin());
            std::transform(i, std::next(i, step), r.begin(), result_it, std::bit_xor<uint8_t>());
            if (step == block_sz)
            {
                std::copy(result_it, std::next(result_it, block_sz), r.begin());
            }
        }
        else
        {
            auto e = cipher.encrypt(r.begin());
            if (step == block_sz)
            {
                std::copy(i, std::next(i, block_sz), r.begin());
            }
            std::transform(i, std::next(i, step), e.begin(), result_it, std::bit_xor<uint8_t>());
        }
        std::advance(i, step);
        std::advance(result_it, step);
        remainning -= step;
    }
    return result;
}
} // namespace focalors
#endif