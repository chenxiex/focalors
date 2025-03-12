#include "focalors.h"
#include <algorithm>
#include <functional>
#include <stdexcept>
#include <vector>
using std::vector;

namespace focalors
{
CFB::CFB(const vector<uint8_t> &key, const block_cipher &cipher, const vector<uint8_t> &z)
    : key(key), cipher(cipher), iv(z)
{
    if (iv.size() != cipher.block_size())
    {
        throw std::invalid_argument("IV size must be equal to block size.");
    }
}
std::vector<uint8_t> CFB::encrypt(std::vector<uint8_t>::const_iterator first,
                                  std::vector<uint8_t>::const_iterator last) const
{
    std::vector<uint8_t> r(iv.begin(), iv.end());
    std::vector<uint8_t> result(std::distance(first, last));
    const auto block_sz = cipher.block_size();
    for (auto i = first; i < last;)
    {
        auto step = std::min(static_cast<size_t>(std::distance(i, last)), block_sz);
        r = cipher.encrypt(r.begin(), r.end(), key);
        auto result_it = result.begin() + std::distance(first, i);
        std::transform(i, i + step, r.begin(), result_it, std::bit_xor<uint8_t>());
        if (static_cast<size_t>(std::distance(result_it, result.end())) >= block_sz)
        {
            std::copy(result_it, result_it + block_sz, r.begin());
        }
        std::advance(i, step);
    }
    return result;
}
std::vector<uint8_t> CFB::decrypt(std::vector<uint8_t>::const_iterator first,
                                  std::vector<uint8_t>::const_iterator last) const
{
    std::vector<uint8_t> r(iv.begin(), iv.end());
    std::vector<uint8_t> result(std::distance(first, last));
    const auto block_sz = cipher.block_size();
    for (auto i = first; i < last;)
    {
        auto step = std::min(static_cast<size_t>(std::distance(i, last)), block_sz);
        auto e = cipher.encrypt(r.begin(), r.end(), key);
        auto result_it = result.begin() + std::distance(first, i);
        if (i + step < last)
        {
            std::copy(i, i + step, r.begin());
        }
        std::transform(i, i + step, e.begin(), result_it, std::bit_xor<uint8_t>());
        std::advance(i, step);
    }
    return result;
}
} // namespace focalors