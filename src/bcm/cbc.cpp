#include "bcm.h"
#include "focalors.h"
#include <iterator>
#include <stdexcept>
#include <vector>

static void check(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                  const focalors::block_cipher &cipher, const std::vector<uint8_t> &z)
{
    if (std::distance(first, last) % cipher.block_size() != 0)
    {
        throw std::invalid_argument("Input size must be a multiple of block size.");
    }
    if (z.size() != cipher.block_size())
    {
        throw std::invalid_argument("Invalid initial vector size.");
    }
}

namespace focalors
{
using std::vector;
std::vector<uint8_t> CBC::encrypt(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                                  const std::vector<uint8_t> &key, const block_cipher &cipher,
                                  const std::vector<uint8_t> &z)
{
    check(first, last, cipher, z);
    auto block_sz = cipher.block_size();
    vector<uint8_t> output(std::distance(first, last));
    vector<uint8_t> ci_1;
    for (auto i = first; i + block_sz <= last; i += block_sz)
    {
        auto block = vector<uint8_t>(i, i + block_sz);
        if (i == first)
        {
            block = bytes_xor(block, z);
        }
        else
        {
            block = bytes_xor(block, ci_1);
        }
        block = cipher.encrypt(block.begin(), block.end(), key);
        ci_1 = block;
        std::move(block.begin(), block.end(), output.begin() + (i - first));
    }
    return output;
}
std::vector<uint8_t> CBC::decrypt(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                                  const std::vector<uint8_t> &key, const block_cipher &cipher,
                                  const std::vector<uint8_t> &z)
{
    check(first, last, cipher, z);
    auto block_sz = cipher.block_size();
    vector<uint8_t> output(std::distance(first, last));
    for (auto i = first; i + block_sz <= last; i += block_sz)
    {
        auto block = cipher.decrypt(i, i + block_sz, key);
        if (i == first)
        {
            block = bytes_xor(block, z);
        }
        else
        {
            block = bytes_xor(block, vector<uint8_t>(i - block_sz, i));
        }
        std::move(block.begin(), block.end(), output.begin() + (i - first));
    }
    return output;
}
} // namespace focalors