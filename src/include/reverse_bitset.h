#pragma once
#ifndef REVERSE_BITSET_H
#define REVERSE_BITSET_H
#include <bitset>
#include <cstdint>
#include <vector>

namespace focalors
{
template <std::size_t N> class reverse_bitset : public std::bitset<N>
{
  public:
    using std::bitset<N>::bitset; // 继承 std::bitset 的构造函数
    template <class T> reverse_bitset<N>(const T &v) noexcept;
    template <class InputIt> reverse_bitset(InputIt first, InputIt last) noexcept;
    constexpr reverse_bitset<N>(const std::bitset<N> &b) noexcept : std::bitset<N>(b)
    {
    }
    constexpr reverse_bitset<N>(std::bitset<N> &&b) noexcept : std::bitset<N>(std::move(b))
    {
    }

    using std::bitset<N>::operator=; // 继承 std::bitset 的赋值运算符

    // 重载[]运算符，支持从左向右索引，返回可修改的引用
    typename focalors::reverse_bitset<N>::reference operator[](std::size_t pos) noexcept;
    // 重载[]运算符，支持从左向右索引，返回只读的值
    constexpr bool operator[](std::size_t pos) const noexcept;

    std::vector<uint8_t> to_vector() const;
};
} // namespace focalors
#include "reverse_bitset_impl.hpp"
#endif