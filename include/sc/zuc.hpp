#pragma once
#ifndef ZUC_HPP
#define ZUC_HPP
#include "../focalors.hpp"
namespace focalors
{
// ZUC_128_EEA3
// public
template <ByteInputIt InputIt, std::sentinel_for<InputIt> Sentinel, std::output_iterator<uint8_t> OutputIt>
auto ZUC_128_EEA3::encrypt(InputIt first, Sentinel last, OutputIt dest)
{
    for (auto i = first; i != last; i++)
    {
        *dest++ = *i ^ generate_keystream_byte();
    }
}
template <ByteInputIt InputIt, std::sentinel_for<InputIt> Sentinel, std::output_iterator<uint8_t> OutputIt>
auto ZUC_128_EEA3::decrypt(InputIt first, Sentinel last, OutputIt dest)
{
    return encrypt(first, last, dest);
}
}; // namespace focalors
#endif