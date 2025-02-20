#include "bcm.h"
#include "focalors.h"
#include <algorithm>
#include <cmath>
#include <iterator>
#include <string>
#include <vector>
using std::string;
using std::vector;

namespace bcm
{
std::vector<uint8_t> ecb(
    std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
    const std::vector<uint8_t> &key, const size_t block_size,
    const std::function<std::vector<uint8_t>(std::vector<uint8_t>::const_iterator, std::vector<uint8_t>::const_iterator,
                                             const std::vector<uint8_t> &)> &cipher_func)
{
    auto block_sz = block_size;
    if (std::distance(first, last) % block_sz != 0)
    {
        throw std::invalid_argument("Input size must be a multiple of block size.");
    }
    vector<uint8_t> output(std::distance(first, last));
    for (auto i = first; i + block_sz <= last; i += block_sz)
    {
        auto block = cipher_func(i, i + block_sz, key);
        std::move(block.begin(), block.end(), output.begin() + (i - first));
    }
    return output;
}
} // namespace bcm

namespace focalors
{
std::vector<uint8_t> ECB::encrypt(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                                 const std::vector<uint8_t> &key, const block_cipher &cipher)
{
    return bcm::ecb(first, last, key, cipher.block_size(),
                    [&cipher](std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                              const std::vector<uint8_t> &key) { return cipher.encrypt(first, last, key); });
}
std::vector<uint8_t> ECB::decrypt(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                                 const std::vector<uint8_t> &key, const block_cipher &cipher)
{
    return bcm::ecb(first, last, key, cipher.block_size(),
                    [&cipher](std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                              const std::vector<uint8_t> &key) { return cipher.decrypt(first, last, key); });
}
} // namespace focalors