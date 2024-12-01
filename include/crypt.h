#pragma once
#ifndef CRYPT_H
#define CRYPT_H
#include <array>
#include <bitset>
#include <functional>
#include <stdexcept>
#include <string>

namespace crypt
{
// type
template <std::size_t N> class bitset : public std::bitset<N>
{
  public:
    using std::bitset<N>::bitset;    // 继承 std::bitset 的构造函数
    using std::bitset<N>::operator=; // 继承 std::bitset 的赋值运算符

    // 重载[]运算符，支持从左向右索引，返回可修改的引用
    typename crypt::bitset<N>::reference operator[](std::size_t pos);
    // 重载[]运算符，支持从左向右索引，返回只读的值
    bool operator[](std::size_t pos) const;

    crypt::bitset<N> operator<<(const size_t &n) const;
    crypt::bitset<N> operator>>(const size_t &n) const;
};
template <std::size_t N> crypt::bitset<N> operator&(const crypt::bitset<N> &lhs, const crypt::bitset<N> &rhs);
template <std::size_t N> crypt::bitset<N> operator|(const crypt::bitset<N> &lhs, const crypt::bitset<N> &rhs);
template <std::size_t N> crypt::bitset<N> operator^(const crypt::bitset<N> &lhs, const crypt::bitset<N> &rhs);

typedef std::bitset<8> byte;

class word : public std::bitset<32>
{
  public:
    using std::bitset<32>::bitset;    // 继承 std::bitset 的构造函数
    using std::bitset<32>::operator=; // 继承 std::bitset 的赋值运算符

    byte get_byte(const std::size_t &pos) const;
    void set_byte(const std::size_t &pos, const byte &value);

    word operator<<(const size_t &n) const;
    word operator>>(const size_t &n) const;
};
word operator&(const word &lhs, const word &rhs);
word operator|(const word &lhs, const word &rhs);
word operator^(const word &lhs, const word &rhs);

// DES
void des_encrypt(crypt::bitset<64> &ciphertext, const crypt::bitset<64> &plaintext, const crypt::bitset<64> &key);
void des_decrypt(crypt::bitset<64> &plaintext, const crypt::bitset<64> &ciphertext, const crypt::bitset<64> &key);

// AES
template <std::size_t BN = 128, std::size_t KN>
void aes_encrypt(crypt::bitset<BN> &ciphertext, const crypt::bitset<BN> &plaintext, const crypt::bitset<KN> &key);
template <std::size_t BN = 128, std::size_t KN>
void aes_decrypt(crypt::bitset<BN> &plaintext, const crypt::bitset<BN> &ciphertext, const crypt::bitset<KN> &key);

// Group mode
template <typename BT, typename KT>
void ecb(std::string &output_string, const std::string &input_string, const KT &key,
         std::function<void(BT &output, const BT &input, const KT &key)> crypt_func);
template <typename BT, typename KT>
void cbc(std::string &output_string, const std::string &input_string, const KT &key, const BT &z, const bool &decrypt,
         std::function<void(BT &output, const BT &input, const KT &key)> crypt_func);
template <typename BT, typename KT>
void ofb(std::string &output_string, const std::string &input_string, const KT &key, const BT &seed, const size_t &s,
         std::function<void(BT &output, const BT &input, const KT &key)> crypt_func);
template <typename BT, typename KT>
void cfb(std::string &output_string, const std::string &input_string, const KT &key, const BT &seed, const size_t &s,
         const bool &decrypt, std::function<void(BT &output, const BT &input, const KT &key)> crypt_func);
} // namespace crypt
#include "bcm_impl.h"
#include "type_impl.h"
#endif // CRYPT_H