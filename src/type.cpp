#include "focalors.h"
#include <stdexcept>
namespace focalors
{
// word
byte word::get_byte(const std::size_t &pos) const
{
    if (pos >= 4)
    {
        throw std::out_of_range("word::get_byte");
    }
    byte result(((*this) << pos * 8 >> 24).to_ulong());
    return result;
}
void word::set_byte(const std::size_t &pos, const byte &value)
{
    if (pos >= 4)
    {
        throw std::out_of_range("word::set_byte");
    }
    word mask(0xff << (3 - pos) * 8);
    mask = ~mask;
    (*this) = ((*this) & mask) | word(value.to_ulong() << (3 - pos) * 8);
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