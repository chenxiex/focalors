#include "focalors.h"
#include <algorithm>
#include <functional>
#include <iterator>
#include <stdexcept>
#include <vector>
using std::vector;

namespace focalors
{
OFB::OFB(const std::vector<uint8_t> &key, const block_cipher &cipher, const std::vector<uint8_t> &iv)
    : key(key), cipher(cipher), iv(iv)
{
    if (iv.size() != cipher.block_size())
    {
        throw std::invalid_argument("IV size must be equal to block size.");
    }
}
std::vector<uint8_t> OFB::encrypt(std::vector<uint8_t>::const_iterator first,
                                  std::vector<uint8_t>::const_iterator last) const
{
    const size_t length = std::distance(first, last);
    std::vector<uint8_t> r(iv.begin(), iv.end());
    std::vector<uint8_t> result(length);
    const auto block_sz = cipher.block_size();
    auto result_it = result.begin();
    auto remainning = length;
    for (auto i = first; i < last;)
    {
        r = cipher.encrypt(r.begin(), r.end(), key);
        auto step = std::min(remainning, block_sz);
        result_it = std::transform(i, std::next(i, step), r.begin(), result_it, std::bit_xor<uint8_t>());
        std::advance(i, step);
        remainning -= step;
    }
    return result;
}
std::vector<uint8_t> OFB::decrypt(std::vector<uint8_t>::const_iterator first,
                                  std::vector<uint8_t>::const_iterator last) const
{
    return encrypt(first, last);
}
} // namespace focalors