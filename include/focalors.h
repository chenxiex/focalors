#pragma once
#ifndef FOCALORS_H
#define FOCALORS_H
#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace focalors
{
// Block cipher
class block_cipher
{
  public:
    /*
     * @brief 获取块大小。
     * @return 块大小。
     */
    virtual size_t block_size() const noexcept = 0;
    /*
     * @brief 加密。
     * @param input 输入数据。
     * @param key 密钥。
     * @return 加密后的数据。
     */
    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t> &input, const std::vector<uint8_t> &key) const = 0;
    /*
     * @brief 解密。
     * @param input 输入数据。
     * @param key 密钥。
     * @return 解密后的数据。
     */
    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t> &input, const std::vector<uint8_t> &key) const = 0;
};

// DES
class DES : public block_cipher
{
  public:
    /*
     * @brief 获取块大小。
     * @return 块大小。
     */
    size_t block_size() const noexcept override;
    /*
     * @brief DES加密。
     * @param input 输入数据。
     * @param key 密钥。
     * @return 加密后的数据。
     */
    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &input, const std::vector<uint8_t> &key) const override;
    /*
     * @brief DES解密。
     * @param input 输入数据。
     * @param key 密钥。
     * @return 解密后的数据。
     */
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &input, const std::vector<uint8_t> &key) const override;

  private:
    /*
     * @brief 检查输入参数是否合法。
     * @param input 输入数据。
     * @param key 密钥。
     * @return true表示合法，false表示不合法。
     */
    bool argument_check(const std::vector<uint8_t> &input, const std::vector<uint8_t> &key) const;
};

// AES
class AES : public block_cipher
{
  public:
    /*
     * @brief 获取块大小。
     * @return 块大小。
     */
    size_t block_size() const noexcept override;
    /*
     * @brief AES加密。
     * @param input 输入数据。
     * @param key 密钥。
     * @return 加密后的数据。
     */
    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &input, const std::vector<uint8_t> &key) const override;
    /*
     * @brief AES解密。
     * @param input 输入数据。
     * @param key 密钥。
     * @return 解密后的数据。
     */
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &input, const std::vector<uint8_t> &key) const override;
};

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
void zuc_init(const std::array<uint8_t, 16> &key, const std::array<uint8_t, 16> &iv);

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
 * @brief 将二进制字符串转换为字节序列。
 * @param binary 二进制字符串。
 * @return 字节序列。
 */
std::vector<uint8_t> binary_to_bytes(const std::string &binary);
/*
 * @brief 将字节序列转换为二进制字符串。
 * @param bytes 字节序列。
 * @return 二进制字符串。
 */
std::string bytes_to_binary(const std::vector<uint8_t> &bytes);
/*
 * @brief 将二进制字符串转换为十六进制字符串。
 * @param binary 二进制字符串。
 * @return 十六进制字符串。
 */
std::string binary_to_hex(const std::string &binary);
/*
 * @brief 将十六进制字符串转换为二进制字符串。
 * @param hex 十六进制字符串。
 * @return 二进制字符串。
 */
std::string hex_to_binary(const std::string &hex);
/*
 * @brief 将十六进制字符串转换为字节序列。
 * @param hex 十六进制字符串。
 * @return 字节序列。
 */
std::vector<uint8_t> hex_to_bytes(const std::string &hex);
/*
 * @brief 将字节序列转换为十六进制字符串。
 * @param bytes 字节序列。
 * @return 十六进制字符串。
 */
std::string bytes_to_hex(const std::vector<uint8_t> &bytes);
} // namespace focalors
#endif // CRYPT_H