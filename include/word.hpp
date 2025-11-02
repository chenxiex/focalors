#pragma once
#ifndef WORD_HPP
#define WORD_HPP
#include "./concepts.hpp"
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

    constexpr word(const std::bitset<32> &b) noexcept : std::bitset<32>(b)
    {
    }
    constexpr word(std::bitset<32> &&b) noexcept : std::bitset<32>(std::move(b))
    {
    }

    constexpr uint8_t get_byte(const std::size_t &pos) const noexcept
    {
        return static_cast<uint8_t>(((*this) << pos * 8 >> 24).to_ulong());
    }
    void set_byte(const std::size_t &pos, const uint8_t &value) noexcept
    {
        if (pos >= 4)
        {
            return;
        }
        word mask(0xff << (3 - pos) * 8);
        mask = ~mask;
        (*this) = ((*this) & mask) | word(static_cast<uint32_t>(value) << (3 - pos) * 8);
    }
};
template <ByteInputIt InputIt, std::sentinel_for<InputIt> Sentinel>
std::vector<focalors::word> bytes_to_word(InputIt first, Sentinel last)
{
    std::vector<word> result;
    for (auto i = first; i + 4 <= last; i += 4)
    {
        focalors::word temp(0);
        for (int j = 0; j < 4; j++)
        {
            temp.set_byte(j, *(i + j));
        }
        result.push_back(temp);
    }
    return result;
}
template <std::output_iterator<uint8_t> OutputIt>
void words_to_bytes(const std::vector<focalors::word> &v, OutputIt dest)
{
    for (auto i : v)
    {
        for (int j = 0; j < 4; j++)
        {
            *dest++ = i.get_byte(j);
        }
    }
}
} // namespace focalors
#endif // WORD_H