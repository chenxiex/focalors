#pragma once
#ifndef CRYPT_IMPL_H
#define CRYPT_IMPL_H
#include <bitset>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace focalors
{
template <std::size_t N> class reverse_bitset : public std::bitset<N>
{
  public:
    using std::bitset<N>::bitset; // 继承 std::bitset 的构造函数
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

class word : public std::bitset<32>
{
  public:
    using std::bitset<32>::bitset;    // 继承 std::bitset 的构造函数
    using std::bitset<32>::operator=; // 继承 std::bitset 的赋值运算符

    uint8_t get_byte(const std::size_t &pos) const;
    void set_byte(const std::size_t &pos, const uint8_t &value);

    word operator<<(const size_t &n) const;
    word operator>>(const size_t &n) const;
};
word operator&(const word &lhs, const word &rhs);
word operator|(const word &lhs, const word &rhs);
word operator^(const word &lhs, const word &rhs);

// reverse_bitset
template <std::size_t N> focalors::reverse_bitset<N>::reverse_bitset(const std::vector<uint8_t> &v)
{
    if (v.size() * sizeof(uint8_t) > N)
    {
        throw std::invalid_argument("The size of vector<uint8_t> is too large.");
    }
    for (auto i : v)
    {
        *this <<= 8;
        *this |= i;
    }
}
template <std::size_t N> std::vector<uint8_t> focalors::reverse_bitset<N>::to_vector() const
{
    std::vector<uint8_t> v;
    auto cnt = 0;
    uint8_t byte = 0;
    for (auto i = 0; i < N; i++)
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
template <std::size_t N> typename focalors::reverse_bitset<N>::reference reverse_bitset<N>::operator[](std::size_t pos)
{
    return std::bitset<N>::operator[](N - 1 - pos); // 左向右索引
}
template <std::size_t N> bool reverse_bitset<N>::operator[](std::size_t pos) const
{
    return std::bitset<N>::operator[](N - 1 - pos); // 左向右索引
}
template <std::size_t N> focalors::reverse_bitset<N> reverse_bitset<N>::operator<<(const size_t &n) const
{
    focalors::reverse_bitset<N> result(*this);
    result <<= n;
    return result;
}
template <std::size_t N> focalors::reverse_bitset<N> reverse_bitset<N>::operator>>(const size_t &n) const
{
    focalors::reverse_bitset<N> result(*this);
    result >>= n;
    return result;
}

template <std::size_t N>
focalors::reverse_bitset<N> operator&(const focalors::reverse_bitset<N> &lhs, const focalors::reverse_bitset<N> &rhs)
{
    focalors::reverse_bitset<N> result(lhs);
    result &= rhs;
    return result;
}
template <std::size_t N>
focalors::reverse_bitset<N> operator|(const focalors::reverse_bitset<N> &lhs, const focalors::reverse_bitset<N> &rhs)
{
    focalors::reverse_bitset<N> result(lhs);
    result |= rhs;
    return result;
}
template <std::size_t N>
focalors::reverse_bitset<N> operator^(const focalors::reverse_bitset<N> &lhs, const focalors::reverse_bitset<N> &rhs)
{
    focalors::reverse_bitset<N> result(lhs);
    result ^= rhs;
    return result;
}
} // namespace focalors
#endif