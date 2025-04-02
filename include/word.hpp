#pragma once
#ifndef WORD_H
#define WORD_H
#include <bitset>
#include <cstdint>
#include <vector>
namespace focalors
{
class word : public std::bitset<32>
{
  public:
    using std::bitset<32>::bitset;    // 继承 std::bitset 的构造函数
    using std::bitset<32>::operator=; // 继承 std::bitset 的赋值运算符

    constexpr word(const std::bitset<32> &b) noexcept : std::bitset<32>(b) {}
    constexpr word(std::bitset<32> &&b) noexcept : std::bitset<32>(std::move(b)) {}

    constexpr uint8_t get_byte(const std::size_t &pos) const noexcept
    {
        return static_cast<uint8_t>(((*this) << pos * 8 >> 24).to_ulong());
    }
    void set_byte(const std::size_t &pos, const uint8_t &value) noexcept;
};
std::vector<focalors::word> bytes_to_word(std::vector<uint8_t>::const_iterator first,
                                          std::vector<uint8_t>::const_iterator last);
std::vector<uint8_t> words_to_bytes(const std::vector<focalors::word> &v);
} // namespace focalors
#endif // WORD_H