#include "word.hpp"
#include <concepts>
#include <stdexcept>
#include <vector>
using std::vector;
namespace focalors
{
void word::set_byte(const std::size_t &pos, const uint8_t &value) noexcept
{
    if (pos >= 4)
    {
        return;
    }
    word mask(0xff << (3 - pos) * 8);
    mask = ~mask;
    (*this) = ((*this) & mask) | word(static_cast<uint32_t>(value) << (3 - pos) * 8);
}
std::vector<uint8_t> words_to_bytes(const std::vector<focalors::word> &v)
{
    vector<uint8_t> result;
    for (auto i : v)
    {
        for (int j = 0; j < 4; j++)
        {
            result.push_back(i.get_byte(j));
        }
    }
    return result;
}
}; // namespace focalors