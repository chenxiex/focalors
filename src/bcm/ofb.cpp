#include "focalors.h"
#include <algorithm>
#include <stdexcept>
#include <vector>
using std::vector;

namespace focalors
{
OFB::OFB(const std::vector<uint8_t> &key, const block_cipher &cipher, const std::vector<uint8_t> &z)
    : key(key), cipher(cipher), z(z){};
std::vector<uint8_t> OFB::encrypt(std::vector<uint8_t>::const_iterator first,
                                  std::vector<uint8_t>::const_iterator last) const
{
    std::vector<uint8_t> r(z.begin(), z.end());
    std::vector<uint8_t> result(std::distance(first, last));
    const auto block_sz = cipher.block_size();
    for (auto i = first; i < last; i += block_sz)
    {
        r = cipher.encrypt(r.begin(), r.end(), key);
        auto j = std::min(i + block_sz, last);
        std::transform(i, j, r.begin(), result.begin() + std::distance(first, i),std::bit_xor<uint8_t>());
    }
    return result;
}
std::vector<uint8_t> OFB::decrypt(std::vector<uint8_t>::const_iterator first,
                                  std::vector<uint8_t>::const_iterator last) const
{
    return encrypt(first, last);
}
} // namespace focalors