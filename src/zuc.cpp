#include "zuc.h"
#include "focalors.h"
#include <array>
#include <bit>
#include <cstdint>
using std::array;
using std::rotl;
#ifdef DEBUG
#include <iostream>
#include <sstream>
#include <string>
using std::cout;
using std::cin;
using std::endl;
using std::string;
#endif

namespace zuc
{
static array<word, 16> s;
static array<word, 4> x;
static word r1;
static word r2;
static word w;
static bool prepared_for_output = false;
uint64_t pow2(const size_t &n)
{
    return uint64_t(1) << n;
}
word h(const word &x)
{
    return (x >> 15) & 0xffff;
}
word l(const word &x)
{
    return x & 0xffff;
}
word addhl(const word &a, const word &b)
{
    return h(a) << 16 | l(b);
}
word addlh(const word &a, const word &b)
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
word add_mod32(word a, word b)
{
    return (a + b) & 0xffffffff;
}
word l1(word x)
{
    return x ^ rotl(x, 2) ^ rotl(x, 10) ^ rotl(x, 18) ^ rotl(x, 24);
}
word l2(word x)
{
    return x ^ rotl(x, 8) ^ rotl(x, 14) ^ rotl(x, 22) ^ rotl(x, 30);
}
word sbox(word x)
{
    focalors::word x1(x);
    for (int i = 0; i < 4; i++)
    {
        if (i & 1)
        {
            x1.set_byte(i, focalors::byte(S1[x1.get_byte(i).to_ulong() >> 4][x1.get_byte(i).to_ulong() & 0xf]));
        }
        else
        {
            x1.set_byte(i, focalors::byte(S0[x1.get_byte(i).to_ulong() >> 4][x1.get_byte(i).to_ulong() & 0xf]));
        }
    }
    return x1.to_ulong();
}
void f()
{
    w = add_mod32(x[0] ^ r1, r2);
    word w1 = add_mod32(r1, x[1]);
    word w2 = r2 ^ x[2];
    r1 = sbox(l1(w1 << 16 | w2 >> 16));
    r2 = sbox(l2(w2 << 16 | w1 >> 16));
}
void lsfr_with_init_mode()
{
    word u = w >> 1;
    word v = (pow2(15) * s[15] + pow2(17) * s[13] + pow2(21) * s[10] + pow2(20) * s[4] + (1 + pow2(8)) * s[0]) %
             (pow2(31) - 1);
    word s16 = (v + u) % (word(1 << 31) - 1);
    if (s16 == 0)
    {
        s16 = word(1 << 31) - 1;
    }
    for (auto i = s.begin(); i + 1 < s.end(); i++)
    {
        *i = *(i + 1);
    }
    *(s.rbegin()) = s16;
}
void lsfr_with_work_mode()
{
    word s16 = (pow2(15) * s[15] + pow2(17) * s[13] + pow2(21) * s[10] + pow2(20) * s[4] + (1 + pow2(8)) * s[0]) %
               (pow2(31) - 1);
    if (s16 == 0)
    {
        s16 = word(1 << 31) - 1;
    }
    for (auto i = s.begin(); i + 1 < s.end(); i++)
    {
        *i = *(i + 1);
    }
    *(s.rbegin()) = s16;
}
void init(const array<byte, 16> &key, const array<byte, 16> &iv)
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
void zuc_init(const array<byte, 16> &key, const array<byte, 16> &iv)
{
    using namespace zuc;
    array<zuc::byte, 16> zuc_key;
    array<zuc::byte, 16> zuc_iv;
    for (auto i = 0; i < 16; i++)
    {
        zuc_key[i] = key[i].to_ulong();
        zuc_iv[i] = iv[i].to_ulong();
    }
    init(zuc_key, zuc_iv);
    bit_reconstruction();
    f();
    lsfr_with_work_mode();
    w = 0;
    prepared_for_output = true;
}
word zuc_output()
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
    return z;
}
} // namespace focalors

#ifdef DEBUG
std::string hex_to_binary_string(const std::string &hex)
{
    std::stringstream ss;
    for (size_t i = 0; i < hex.size(); ++i)
    {
        unsigned int n;
        std::stringstream(hex.substr(i, 1)) >> std::hex >> n;
        ss << std::bitset<4>(n);
    }
    return ss.str();
}
std::string binary_to_hex_string(const std::string &binary)
{
    std::stringstream ss;
    for (size_t i = 0; i < binary.size(); i += 4)
    {
        std::bitset<4> b(binary.substr(i, 4));
        ss << std::hex << b.to_ulong();
    }
    return ss.str();
}

int main()
{
    string key,iv;
    cout<<"输入key（16进制连续输入）：";
    cin>>key;
    cout<<"输入iv（16进制连续输入）：";
    cin>>iv;
    cout<<"输入输出次数：";
    int n;
    cin>>n;
    key = hex_to_binary_string(key);
    iv = hex_to_binary_string(iv);
    array<focalors::byte, 16> zuc_key;
    array<focalors::byte, 16> zuc_iv;
    for (auto i = 0; i < 16; i++)
    {
        zuc_key[i] = focalors::byte(key.substr(i * 8, 8));
        zuc_iv[i] = focalors::byte(iv.substr(i * 8, 8));
    }
    focalors::zuc_init(zuc_key, zuc_iv);
    for (auto i = 0; i < n; i++)
    {
        cout << std::hex << focalors::zuc_output().to_ullong() << endl;
    }
    return 0;
}
#endif