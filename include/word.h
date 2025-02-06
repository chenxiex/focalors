#pragma once
#ifndef WORD_H
#define WORD_H
#include <bitset>
#include <cstdint>
namespace focalors
{
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
} // namespace focalors
#endif // WORD_H