#pragma once
#ifndef REVERSE_BITSET_IMPL_H
#define REVERSE_BITSET_IMPL_H
#include "reverse_bitset.h"
namespace focalors
{
template <std::size_t N> template <class T> focalors::reverse_bitset<N>::reverse_bitset(const T &v) noexcept
{
    using ValueType = typename T::value_type;
    auto unit_bit_size = sizeof(ValueType) * 8;
    for (auto i : v)
    {
        *this <<= unit_bit_size;
        *this |= i;
    }
}
template <std::size_t N>
template <class InputIt>
focalors::reverse_bitset<N>::reverse_bitset(InputIt first, InputIt last) noexcept
{
    using ValueType = typename std::iterator_traits<InputIt>::value_type;
    auto unit_bit_size = sizeof(ValueType) * 8;
    for (auto i = first; i != last; i++)
    {
        *this <<= unit_bit_size;
        *this |= *i;
    }
}
template <std::size_t N> std::vector<uint8_t> focalors::reverse_bitset<N>::to_vector() const
{
    std::vector<uint8_t> v;
    auto cnt = 0;
    uint8_t byte = 0;
    for (size_t i = 0; i < N; i++)
    {
        byte <<= 1;
        byte |= (*this)[i];
        cnt++;
        if (cnt == 8)
        {
            v.push_back(byte);
            cnt = 0;
            byte = 0;
        }
    }
    return v;
}
template <std::size_t N> typename focalors::reverse_bitset<N>::reference reverse_bitset<N>::operator[](std::size_t pos) noexcept
{
    return std::bitset<N>::operator[](N - 1 - pos); // 左向右索引
}
template <std::size_t N> constexpr bool reverse_bitset<N>::operator[](std::size_t pos) const noexcept
{
    return std::bitset<N>::operator[](N - 1 - pos); // 左向右索引
}
} // namespace focalors
#endif