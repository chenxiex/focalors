#pragma once
#ifndef DES_HPP
#define DES_HPP
#include "focalors.hpp"
#include "reverse_bitset.hpp"
#include <array>

namespace focalors
{
// DES
// public
inline DES::DES(const auto &key)
{
    set_key(key);
}
inline void DES::set_key(const auto &key)
{
    subkeys_ = generate_subkeys(reverse_bitset<64>(key));
}
constexpr size_t DES::block_size() const noexcept
{
    return block_size_;
}
template <std::input_iterator InputIt, std::sentinel_for<InputIt> Sentinel>
inline auto DES::encrypt(InputIt first, Sentinel last) const noexcept
{
    reverse_bitset<64> data(first, last);
    data = des_encrypt(data, subkeys_);
    return std::vector<uint8_t>(data);
}
template <std::input_iterator InputIt, std::sentinel_for<InputIt> Sentinel>
inline auto DES::decrypt(InputIt first, Sentinel last) const noexcept
{
    reverse_bitset<64> data(first, last);
    data = des_decrypt(data, subkeys_);
    return std::vector<uint8_t>(data);
}
} // namespace focalors
#endif // DES_H