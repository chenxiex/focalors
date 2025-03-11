#include "bcm.h"
#include "focalors.h"
#include <algorithm>
#include <functional>
#include <iterator>
#include <stdexcept>
#include <vector>

namespace focalors
{
using std::vector;
CBC::CBC(const std::vector<uint8_t> &key, const block_cipher &cipher, const std::vector<uint8_t> &iv)
    : key(key), cipher(cipher), iv(iv)
{
    if (iv.size() != cipher.block_size())
    {
        throw std::invalid_argument("IV size must be equal to block size");
    }
};
std::vector<uint8_t> CBC::encrypt(std::vector<uint8_t>::const_iterator first,
                                  std::vector<uint8_t>::const_iterator last) const
{
    auto block_sz = cipher.block_size();
    if (std::distance(first, last) % block_sz)
    {
        throw std::invalid_argument("Input size must be a multiple of block size");
    }
    vector<uint8_t> output(std::distance(first, last));
    for (auto i = first; i + block_sz <= last; i += block_sz)
    {
        vector<uint8_t> block(block_sz);
        auto output_it = output.begin() + (i - first);
        if (i == first)
        {
            std::transform(i, i + block_sz, iv.begin(), block.begin(), std::bit_xor<uint8_t>());
        }
        else
        {
            std::transform(i, i + block_sz, output_it - block_sz, block.begin(), std::bit_xor<uint8_t>());
        }
        block = cipher.encrypt(block.begin(), block.end(), key);
        std::move(block.begin(), block.end(), output_it);
    }
    return output;
}
std::vector<uint8_t> CBC::decrypt(std::vector<uint8_t>::const_iterator first,
                                  std::vector<uint8_t>::const_iterator last) const
{
    auto block_sz = cipher.block_size();
    if (std::distance(first, last) % block_sz)
    {
        throw std::invalid_argument("Input size must be a multiple of block size");
    }
    vector<uint8_t> output(std::distance(first, last));
    for (auto i = first; i + block_sz <= last; i += block_sz)
    {
        auto block = cipher.decrypt(i, i + block_sz, key);
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
} // namespace focalors