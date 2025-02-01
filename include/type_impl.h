#pragma once
#ifndef CRYPT_IMPL_H
#define CRYPT_IMPL_H
#include "crypt.h"
namespace crypt
{
// bitset
template <std::size_t N> typename crypt::reverse_bitset<N>::reference reverse_bitset<N>::operator[](std::size_t pos)
{
    return std::bitset<N>::operator[](N - 1 - pos); // 左向右索引
}
template <std::size_t N> bool reverse_bitset<N>::operator[](std::size_t pos) const
{
    return std::bitset<N>::operator[](N - 1 - pos); // 左向右索引
}
template <std::size_t N> crypt::reverse_bitset<N> reverse_bitset<N>::operator<<(const size_t &n) const
{
    crypt::reverse_bitset<N> result(*this);
    result <<= n;
    return result;
}
template <std::size_t N> crypt::reverse_bitset<N> reverse_bitset<N>::operator>>(const size_t &n) const
{
    crypt::reverse_bitset<N> result(*this);
    result >>= n;
    return result;
}
template <std::size_t N> crypt::reverse_bitset<N> operator&(const crypt::reverse_bitset<N> &lhs, const crypt::reverse_bitset<N> &rhs)
{
    crypt::reverse_bitset<N> result(lhs);
    result &= rhs;
    return result;
}
template <std::size_t N> crypt::reverse_bitset<N> operator|(const crypt::reverse_bitset<N> &lhs, const crypt::reverse_bitset<N> &rhs)
{
    crypt::reverse_bitset<N> result(lhs);
    result |= rhs;
    return result;
}
template <std::size_t N> crypt::reverse_bitset<N> operator^(const crypt::reverse_bitset<N> &lhs, const crypt::reverse_bitset<N> &rhs)
{
    crypt::reverse_bitset<N> result(lhs);
    result ^= rhs;
    return result;
}
} // namespace crypt
#endif