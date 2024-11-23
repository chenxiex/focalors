#ifndef CRYPT_H
#define CRYPT_H
#include "group-mode.h"
#include <bitset>
#include <functional>
#include <stdexcept>
#include <string>

namespace crypt
{
template <std::size_t N> class bitset : public std::bitset<N>
{
  public:
    using std::bitset<N>::bitset;    // 继承 std::bitset 的构造函数
    using std::bitset<N>::operator=; // 继承 std::bitset 的赋值运算符

    // 重载[]运算符，支持从左向右索引，返回可修改的引用
    typename std::bitset<N>::reference operator[](std::size_t pos)
    {
        return std::bitset<N>::operator[](N - 1 - pos); // 左向右索引
    }

    // 重载[]运算符，支持从左向右索引，返回只读的值
    bool operator[](std::size_t pos) const
    {
        return std::bitset<N>::operator[](N - 1 - pos); // 左向右索引
    }

    bitset<N> operator^(const bitset<N> &other) const
    {
        bitset<N> result(*this);
        result ^= other;
        return result;
    }
};

// DES
void des_encrypt(crypt::bitset<64> &ciphertext, const crypt::bitset<64> &plaintext, const crypt::bitset<64> &key);
void des_decrypt(crypt::bitset<64> &plaintext, const crypt::bitset<64> &ciphertext, const crypt::bitset<64> &key);

// Group mode
template <typename T>
void ecb(std::string &output_string, const std::string &input_string, const T &key,
         std::function<void(T &output, const T &input, const T &key)> crypt_func);
template <typename T>
void cbc(std::string &output_string, const std::string &input_string, const T &key, const T &z, const bool &decrypt,
         std::function<void(T &output, const T &input, const T &key)> crypt_func);
template <typename T>
void ofb(std::string &output_string, const std::string &input_string, const T &key, const T &seed, const size_t &s,
         std::function<void(T &output, const T &input, const T &key)> crypt_func);
template <typename T>
void cfb(std::string &output_string, const std::string &input_string, const T &key, const T &seed, const size_t &s,
         const bool &decrypt, std::function<void(T &output, const T &input, const T &key)> crypt_func);
} // namespace crypt

#endif // CRYPT_H