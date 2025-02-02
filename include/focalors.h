#pragma once
#ifndef CRYPT_H
#define CRYPT_H
#include <array>
#include <bitset>
#include <cstdint>
#include <functional>
#include <string>

namespace focalors
{
//type
template <std::size_t N> class reverse_bitset : public std::bitset<N>
{
  public:
    using std::bitset<N>::bitset; // 继承 std::bitset 的构造函数
    reverse_bitset<N>(const std::vector<uint8_t> &v);
    using std::bitset<N>::operator=; // 继承 std::bitset 的赋值运算符

    // 重载[]运算符，支持从左向右索引，返回可修改的引用
    typename focalors::reverse_bitset<N>::reference operator[](std::size_t pos);
    // 重载[]运算符，支持从左向右索引，返回只读的值
    bool operator[](std::size_t pos) const;

    focalors::reverse_bitset<N> operator<<(const size_t &n) const;
    focalors::reverse_bitset<N> operator>>(const size_t &n) const;

    std::vector<uint8_t> to_vector() const;
};
template <std::size_t N>
focalors::reverse_bitset<N> operator&(const focalors::reverse_bitset<N> &lhs, const focalors::reverse_bitset<N> &rhs);
template <std::size_t N>
focalors::reverse_bitset<N> operator|(const focalors::reverse_bitset<N> &lhs, const focalors::reverse_bitset<N> &rhs);
template <std::size_t N>
focalors::reverse_bitset<N> operator^(const focalors::reverse_bitset<N> &lhs, const focalors::reverse_bitset<N> &rhs);

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

/*
 * DES加密或解密。
 *
 * @param input 输入数据。
 * @param key 密钥。
 * @param encrypt true表示加密，false表示解密。
 * @return 加密或解密后的数据。
 */
std::vector<uint8_t> des(const std::vector<uint8_t> &input, const std::vector<uint8_t> &key, bool encrypt);

// AES
template <std::size_t BN = 128, std::size_t KN>
void aes_encrypt(focalors::reverse_bitset<BN> &ciphertext, const focalors::reverse_bitset<BN> &plaintext,
                 const focalors::reverse_bitset<KN> &key);
template <std::size_t BN = 128, std::size_t KN>
void aes_decrypt(focalors::reverse_bitset<BN> &plaintext, const focalors::reverse_bitset<BN> &ciphertext,
                 const focalors::reverse_bitset<KN> &key);

// Block cipher mode
template <typename BT, typename KT>
void ecb(std::string &output_string, const std::string &input_string, const KT &key,
         std::function<void(BT &output, const BT &input, const KT &key)> crypt_func);
template <typename BT, typename KT>
void ecb_stream_cipher_padding(std::string &output_string, const std::string &input_string, const KT &key,
                               const BT &seed, const bool &decrypt,
                               std::function<void(BT &output, const BT &input, const KT &key)> crypt_func,
                               std::function<void(BT &output, const BT &input, const KT &key)> encrypt_func);
template <typename BT, typename KT>
void ecb_ciphertext_stealing_padding(std::string &output_string, const std::string input_string, const KT &key,
                                     const BT &seed, const size_t &s, const bool &decrypt,
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
template <typename BT, typename KT>
void x_cbc(std::string &output_string, const std::string &input_string, const KT &k1, const BT &k2, const BT &k3,
           const BT &z, const bool &decrypt, const size_t padding,
           std::function<void(BT &output, const BT &input, const KT &key)> crypt_func);
template <typename BT, typename KT>
void ctr(std::string &output_string, const std::string &input_string, const KT &key, const std::string &seed_string,
         std::function<void(BT &output, const BT &input, const KT &key)> crypt_func);

// ZUC
void zuc_init(const std::array<byte, 16> &key, const std::array<byte, 16> &iv);
word zuc_output();

// RSA
void rsa_generate_key(std::string &e, std::string &d, std::string &n, const int &base);
std::string rsa_encrypt(const std::string &m, const std::string &e, const std::string &n, const int &base);
std::string rsa_decrypt(const std::string &c, const std::string &d, const std::string &n, const int &base);

// ElGamal
void elgamal_generate_key(std::string &p, std::string &a, std::string &d, std::string &y, const int &base);
void elgamal_encrypt(std::string &c1, std::string &c2, const std::string &m, const std::string &p, const std::string &a,
                     const std::string &y, const int &base);
void elgamal_decrypt(std::string &m, const std::string &c1, const std::string &c2, const std::string &d,
                     const std::string &p, const int &base);

// utils

/*
 * 将二进制字符串转换为字节序列。字符串不能被8整除的部分将被忽略。
 *
 * @param binary 二进制字符串。
 * @return 字节序列。
 */
std::vector<uint8_t> binary_to_bytes(const std::string &binary);
/*
 * 将字节序列转换为二进制字符串。
 *
 * @param bytes 字节序列。
 * @return 二进制字符串。
 */
std::string bytes_to_binary(const std::vector<uint8_t> &bytes);
} // namespace focalors
#endif // CRYPT_H