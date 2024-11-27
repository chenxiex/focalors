#pragma once
#ifndef CRYPT_IMPL_H
#define CRYPT_IMPL_H
#include "crypt.h"
namespace crypt
{
// bitset
template <std::size_t N> typename crypt::bitset<N>::reference bitset<N>::operator[](std::size_t pos)
{
    return std::bitset<N>::operator[](N - 1 - pos); // 左向右索引
}
template <std::size_t N> bool bitset<N>::operator[](std::size_t pos) const
{
    return std::bitset<N>::operator[](N - 1 - pos); // 左向右索引
}
template <std::size_t N> crypt::bitset<N> bitset<N>::operator<<(const size_t &n) const
{
    crypt::bitset<N> result(*this);
    result <<= n;
    return result;
}
template <std::size_t N> crypt::bitset<N> bitset<N>::operator>>(const size_t &n) const
{
    crypt::bitset<N> result(*this);
    result >>= n;
    return result;
}
template <std::size_t N> crypt::bitset<N> operator&(const crypt::bitset<N> &lhs, const crypt::bitset<N> &rhs)
{
    crypt::bitset<N> result(lhs);
    result &= rhs;
    return result;
}
template <std::size_t N> crypt::bitset<N> operator|(const crypt::bitset<N> &lhs, const crypt::bitset<N> &rhs)
{
    crypt::bitset<N> result(lhs);
    result |= rhs;
    return result;
}
template <std::size_t N> crypt::bitset<N> operator^(const crypt::bitset<N> &lhs, const crypt::bitset<N> &rhs)
{
    crypt::bitset<N> result(lhs);
    result ^= rhs;
    return result;
}
} // namespace crypt
#endif