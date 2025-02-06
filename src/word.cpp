#include "../include/word.h"
#include <stdexcept>
namespace focalors
{
uint8_t word::get_byte(const std::size_t &pos) const
{
    if (pos >= 4)
    {
        throw std::out_of_range("word::get_byte");
    }
    uint8_t result(((*this) << pos * 8 >> 24).to_ulong());
    return result;
}
void word::set_byte(const std::size_t &pos, const uint8_t &value)
{
    if (pos >= 4)
    {
        throw std::out_of_range("word::set_byte");
    }
    word mask(0xff << (3 - pos) * 8);
    mask = ~mask;
    (*this) = ((*this) & mask) | word(static_cast<uint32_t>(value) << (3 - pos) * 8);
}
word word::operator<<(const size_t &n) const
{
    word result(*this);
    result <<= n;
    return result;
}
word word::operator>>(const size_t &n) const
{
    word result(*this);
    result >>= n;
    return result;
}
word operator&(const word &lhs, const word &rhs)
{
    word result(lhs);
    result &= rhs;
    return result;
}
word operator|(const word &lhs, const word &rhs)
{
    word result(lhs);
    result |= rhs;
    return result;
}
word operator^(const word &lhs, const word &rhs)
{
    word result(lhs);
    result ^= rhs;
    return result;
}
}; // namespace focalors