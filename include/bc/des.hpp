#pragma once
#ifndef DES_HPP
#define DES_HPP
#include "focalors.hpp"
#include "reverse_bitset.hpp"
#include <cstdint>
#include <vector>

namespace focalors
{
// DES
// public
DES::DES(const auto &key)
{
    set_key(key);
}
void DES::set_key(const auto &key)
{
    subkeys_ = generate_subkeys(reverse_bitset<64>(key));
}
constexpr size_t DES::block_size() const noexcept
{
    return block_size_;
}
template <std::input_iterator InputIt, std::output_iterator<uint8_t> OutputIt> auto DES::encrypt(InputIt first, OutputIt dest) const
{
    reverse_bitset<64> data(first, first + block_size());
    data = des_encrypt(data, subkeys_);
    data.to_container<uint8_t>(dest);
}
template <std::input_iterator InputIt, std::output_iterator<uint8_t> OutputIt> auto DES::decrypt(InputIt first, OutputIt dest) const
{
    reverse_bitset<64> data(first, first + block_size());
    data = des_decrypt(data, subkeys_);
    data.to_container<uint8_t>(dest);
}
} // namespace focalors
#endif // DES_H