#include "zuc.h"
#include "focalors.hpp"
#include "word.h"
#include <array>
#include <cstdint>
#include <limits>
#include <stdexcept>
using std::array;

namespace zuc
{
static array<uint16_t, 16> s;
static array<uint16_t, 4> x;
static uint16_t r1;
static uint16_t r2;
static uint16_t w;
static bool prepared_for_output = false;
template <typename T> constexpr T rotl(const T &x, const size_t s)
{
    return (x << s) | (x >> (std::numeric_limits<T>::digits - s));
}
constexpr uint64_t pow2(const size_t &n)
{
    return uint64_t(1) << n;
}
constexpr uint16_t h(const uint16_t &x)
{
    return (x >> 15) & 0xffff;
}
constexpr uint16_t l(const uint16_t &x)
{
    return x & 0xffff;
}
constexpr uint16_t addhl(const uint16_t &a, const uint16_t &b)
{
    return h(a) << 16 | l(b);
}
constexpr uint16_t addlh(const uint16_t &a, const uint16_t &b)
{
    return l(a) << 16 | h(b);
}
void bit_reconstruction()
{
    x[0] = addhl(s[15], s[14]);
    x[1] = addlh(s[11], s[9]);
    x[2] = addlh(s[7], s[5]);
    x[3] = addlh(s[2], s[0]);
}
constexpr uint16_t add_mod32(uint16_t a, uint16_t b)
{
    return (a + b) & 0xffffffff;
}
constexpr uint16_t l1(uint16_t x)
{
    return x ^ rotl(x, 2) ^ rotl(x, 10) ^ rotl(x, 18) ^ rotl(x, 24);
}
constexpr uint16_t l2(uint16_t x)
{
    return x ^ rotl(x, 8) ^ rotl(x, 14) ^ rotl(x, 22) ^ rotl(x, 30);
}
uint16_t sbox(uint16_t x)
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
void f()
{
    w = add_mod32(x[0] ^ r1, r2);
    uint16_t w1 = add_mod32(r1, x[1]);
    uint16_t w2 = r2 ^ x[2];
    r1 = sbox(l1(w1 << 16 | w2 >> 16));
    r2 = sbox(l2(w2 << 16 | w1 >> 16));
}
void lsfr_with_init_mode()
{
    uint16_t u = w >> 1;
    uint16_t v = (pow2(15) * s[15] + pow2(17) * s[13] + pow2(21) * s[10] + pow2(20) * s[4] + (1 + pow2(8)) * s[0]) %
                 (pow2(31) - 1);
    uint16_t s16 = (v + u) % (uint16_t(1 << 31) - 1);
    if (s16 == 0)
    {
        s16 = uint16_t(1 << 31) - 1;
    }
    for (auto i = s.begin(); i + 1 < s.end(); i++)
    {
        *i = *(i + 1);
    }
    *(s.rbegin()) = s16;
}
void lsfr_with_work_mode()
{
    uint16_t s16 = (pow2(15) * s[15] + pow2(17) * s[13] + pow2(21) * s[10] + pow2(20) * s[4] + (1 + pow2(8)) * s[0]) %
                   (pow2(31) - 1);
    if (s16 == 0)
    {
        s16 = uint16_t(1 << 31) - 1;
    }
    for (auto i = s.begin(); i + 1 < s.end(); i++)
    {
        *i = *(i + 1);
    }
    *(s.rbegin()) = s16;
}
void init(const array<uint8_t, 16> &key, const array<uint8_t, 16> &iv)
{
    for (auto i = 0; i < 16; i++)
    {
        s[i] = (key[i] << 23) | (D[i] << 8) | iv[i];
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
} // namespace zuc

namespace focalors
{
void zuc_init(const array<uint8_t, 16> &key, const array<uint8_t, 16> &iv)
{
    using namespace zuc;
    array<uint8_t, 16> zuc_key;
    array<uint8_t, 16> zuc_iv;
    for (auto i = 0; i < 16; i++)
    {
        zuc_key[i] = key[i];
        zuc_iv[i] = iv[i];
    }
    init(zuc_key, zuc_iv);
    bit_reconstruction();
    f();
    lsfr_with_work_mode();
    w = 0;
    prepared_for_output = true;
}
uint16_t zuc_output()
{
    using namespace zuc;
    if (!prepared_for_output)
    {
        throw std::runtime_error("zuc_output() called before zuc_init()");
    }
    bit_reconstruction();
    f();
    focalors::word z(w ^ x[3]);
    lsfr_with_work_mode();
    return z.to_ulong();
}
} // namespace focalors