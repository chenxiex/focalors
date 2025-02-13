#include "test.h"
#include "focalors.h"
#include <iterator>
#include <stdexcept>
#include <vector>

size_t simple_block_cipher::block_size() const noexcept
{
    return 8;
}

std::vector<uint8_t> simple_block_cipher::encrypt(std::vector<uint8_t>::const_iterator first,
                                                  std::vector<uint8_t>::const_iterator last,
                                                  const std::vector<uint8_t> &key) const
{
    if (std::distance(first, last) != block_size())
    {
        throw std::invalid_argument("Invalid block size");
    }
    if (key.size() != block_size())
    {
        throw std::invalid_argument("Invalid key size");
    }
    std::vector<uint8_t> output;
    for (auto it = first, keyit = key.begin(); it != last; ++it, ++keyit)
    {
        output.push_back(*it ^ *keyit);
    }
    return output;
}

std::vector<uint8_t> simple_block_cipher::decrypt(std::vector<uint8_t>::const_iterator first,
                                                  std::vector<uint8_t>::const_iterator last,
                                                  const std::vector<uint8_t> &key) const
{
    if (std::distance(first, last) != block_size())
    {
        throw std::invalid_argument("Invalid block size");
    }
    if (key.size() != block_size())
    {
        throw std::invalid_argument("Invalid key size");
    }
    std::vector<uint8_t> output;
    for (auto it = first, keyit = key.begin(); it != last; ++it, ++keyit)
    {
        output.push_back(*it ^ *keyit);
    }
    return output;
}