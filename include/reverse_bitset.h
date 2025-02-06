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

    /*
     * 从字节序列构造 reverse_bitset。请确保字节序列长度与位数 N 匹配。
     *
     * @param v 字节序列。
     */
    reverse_bitset<N>(const std::vector<uint8_t> &v);
    using std::bitset<N>::operator=; // 继承 std::bitset 的赋值运算符

    // 重载[]运算符，支持从左向右索引，返回可修改的引用
    typename focalors::reverse_bitset<N>::reference operator[](std::size_t pos);
    // 重载[]运算符，支持从左向右索引，返回只读的值
    bool operator[](std::size_t pos) const;

    focalors::reverse_bitset<N> operator<<(const size_t &n) const;
    focalors::reverse_bitset<N> operator>>(const size_t &n) const;

    std::vector<uint8_t> to_vector() const;
};
template <std::size_t N>
focalors::reverse_bitset<N> operator&(const focalors::reverse_bitset<N> &lhs, const focalors::reverse_bitset<N> &rhs);
template <std::size_t N>
focalors::reverse_bitset<N> operator|(const focalors::reverse_bitset<N> &lhs, const focalors::reverse_bitset<N> &rhs);
template <std::size_t N>
focalors::reverse_bitset<N> operator^(const focalors::reverse_bitset<N> &lhs, const focalors::reverse_bitset<N> &rhs);
} // namespace focalors
#include "../src/reverse_bitset_impl.hpp"
#endif