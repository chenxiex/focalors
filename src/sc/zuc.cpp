#include "focalors.hpp"
#include "word.hpp"
#include <array>
#include <bit>
#include <cstdint>
#include <limits>
#include <stdexcept>
constexpr uint64_t pow2(const size_t &n) noexcept
{
    return uint64_t(1) << n;
}
constexpr uint32_t h(const uint32_t &x) noexcept
{
    return (x >> 15) & 0xffff;
}
constexpr uint32_t l(const uint32_t &x) noexcept
{
    return x & 0xffff;
}
constexpr uint32_t addhl(const uint32_t &a, const uint32_t &b) noexcept
{
    return h(a) << 16 | l(b);
}
constexpr uint32_t addlh(const uint32_t &a, const uint32_t &b) noexcept
{
    return l(a) << 16 | h(b);
}
constexpr uint32_t add_mod32(uint32_t a, uint32_t b) noexcept
{
    return (a + b) & 0xffffffff;
}
constexpr uint32_t l1(uint32_t x) noexcept
{
    return x ^ std::rotl(x, 2) ^ std::rotl(x, 10) ^ std::rotl(x, 18) ^ std::rotl(x, 24);
}
constexpr uint32_t l2(uint32_t x) noexcept
{
    return x ^ std::rotl(x, 8) ^ std::rotl(x, 14) ^ std::rotl(x, 22) ^ std::rotl(x, 30);
}

namespace focalors
{
// ZUC
// public
ZUC::ZUC(const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv)
{
    prepare(key, iv);
}
uint32_t ZUC::generate_keystream_word()
{
    bit_reconstruction();
    f();
    uint32_t z = w ^ x[3];
    lsfr_with_work_mode();
    return z;
}
uint8_t ZUC::generate_keystream_byte()
{
    if (keystream_word_cache != 0)
    {
        auto byte = (keystream_word_cache & 0xff000000) >> 24;
        keystream_word_cache <<= 8;
        return byte;
    }
    keystream_word_cache = generate_keystream_word();
    return generate_keystream_byte();
}
// private
void ZUC::bit_reconstruction() noexcept
{
    x[0] = addhl(s[15], s[14]);
    x[1] = addlh(s[11], s[9]);
    x[2] = addlh(s[7], s[5]);
    x[3] = addlh(s[2], s[0]);
}
uint32_t ZUC::sbox(uint32_t x)
{
    focalors::word x1(x);
    for (int i = 0; i < 4; i++)
    {
        if (i & 1)
        {
            x1.set_byte(i, S1[x1.get_byte(i) >> 4][x1.get_byte(i) & 0xf]);
        }
        else
        {
            x1.set_byte(i, S0[x1.get_byte(i) >> 4][x1.get_byte(i) & 0xf]);
        }
    }
    return x1.to_ulong();
}
void ZUC::f()
{
    w = add_mod32(x[0] ^ r1, r2);
    auto w1 = add_mod32(r1, x[1]);
    auto w2 = r2 ^ x[2];
    r1 = sbox(l1(w1 << 16 | w2 >> 16));
    r2 = sbox(l2(w2 << 16 | w1 >> 16));
}
void ZUC::lsfr_with_init_mode()
{
    auto u = w >> 1;
    auto v = (pow2(15) * s[15] + pow2(17) * s[13] + pow2(21) * s[10] + pow2(20) * s[4] + (1 + pow2(8)) * s[0]) %
             (pow2(31) - 1);
    auto s16 = (v + u) % (pow2(31) - 1);
    if (s16 == 0)
    {
        s16 = pow2(31) - 1;
    }
    for (auto i = s.begin(); i + 1 < s.end(); i++)
    {
        *i = *(i + 1);
    }
    *(s.rbegin()) = s16;
}
void ZUC::lsfr_with_work_mode()
{
    auto s16 = (pow2(15) * s[15] + pow2(17) * s[13] + pow2(21) * s[10] + pow2(20) * s[4] + (1 + pow2(8)) * s[0]) %
               (pow2(31) - 1);
    if (s16 == 0)
    {
        s16 = pow2(31) - 1;
    }
    for (auto i = s.begin(); i + 1 < s.end(); i++)
    {
        *i = *(i + 1);
    }
    *(s.rbegin()) = s16;
}
void ZUC::init(const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv)
{
    for (auto i = 0; i < 16; i++)
    {
        s[i] =
            (static_cast<uint32_t>(key[i]) << 23) | (static_cast<uint32_t>(D[i]) << 8) | static_cast<uint32_t>(iv[i]);
    }
    r1 = 0;
    r2 = 0;
    for (auto i = 0; i < 32; i++)
    {
        bit_reconstruction();
        f();
        lsfr_with_init_mode();
    }
}
void ZUC::prepare(const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv)
{
    if (key.size() != 16 || iv.size() != 16)
    {
        throw std::invalid_argument("ZUC key and iv must be 16 bytes long");
    }
    init(key, iv);
    bit_reconstruction();
    f();
    lsfr_with_work_mode();
    w = 0;
}

// ZUC_128_EEA3
// public
ZUC_128_EEA3::ZUC_128_EEA3(const uint32_t count, const uint8_t bearer, const bool direction,
                           const std::vector<uint8_t> &key)
    : ZUC(key, generate_iv(count, bearer, direction))
{
}
// private
std::vector<uint8_t> ZUC_128_EEA3::generate_iv(const uint32_t count, const uint8_t bearer, const bool direction)
{
    auto iv = std::vector<uint8_t>(16);
    auto count_word = focalors::word(count);
    for (auto i = 0; i < 4; i++)
    {
        iv[i] = count_word.get_byte(i);
    }
    iv[4] = (bearer << 3) | (direction << 2);
    iv[5] = iv[6] = iv[7] = 0;
    for (auto i = 8; i < 16; i++)
    {
        iv[i] = iv[i - 8];
    }
    return iv;
}
} // namespace focalors