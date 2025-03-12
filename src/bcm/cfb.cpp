#include "focalors.h"
#include <algorithm>
#include <functional>
#include <stdexcept>
#include <vector>
using std::vector;

template <bool encrypt>
std::vector<uint8_t> process(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                             const vector<uint8_t> &key, const std::vector<uint8_t> &iv,
                             const focalors::block_cipher &cipher)
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
        if (encrypt)
        {
            r = cipher.encrypt(r.begin(), r.end(), key);
            std::transform(i, std::next(i, step), r.begin(), result_it, std::bit_xor<uint8_t>());
            if (static_cast<size_t>(std::distance(result_it, result.end())) >= block_sz)
            {
                std::copy(result_it, std::next(result_it, block_sz), r.begin());
            }
        }
        else
        {
            auto e = cipher.encrypt(r.begin(), r.end(), key);
            if (i + step < last)
            {
                std::copy(i, std::next(i, step), r.begin());
            }
            std::transform(i, std::next(i, step), e.begin(), result_it, std::bit_xor<uint8_t>());
        }
        std::advance(i, step);
        std::advance(result_it, step);
        remainning -= step;
    }
    return result;
}

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
    return process<true>(first, last, key, iv, cipher);
}
std::vector<uint8_t> CFB::decrypt(std::vector<uint8_t>::const_iterator first,
                                  std::vector<uint8_t>::const_iterator last) const
{
    return process<false>(first, last, key, iv, cipher);
}
} // namespace focalors