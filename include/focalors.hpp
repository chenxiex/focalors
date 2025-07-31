#pragma once
#include <memory>
#include <stdexcept>
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
    virtual ~block_cipher() = default;
    /*
     * @brief 获取块大小。
     * @return 块大小。
     */
    virtual size_t block_size() const noexcept = 0;
    /*
     * @brief 加密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @param key 密钥。
     * @return 加密后的数据。
     */
    virtual std::vector<uint8_t> encrypt(std::vector<uint8_t>::const_iterator first,
                                         std::vector<uint8_t>::const_iterator last,
                                         const std::vector<uint8_t> &key) const = 0;
    /*
     * @brief 解密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @param key 密钥。
     * @return 解密后的数据。
     */
    virtual std::vector<uint8_t> decrypt(std::vector<uint8_t>::const_iterator first,
                                         std::vector<uint8_t>::const_iterator last,
                                         const std::vector<uint8_t> &key) const = 0;
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
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @param key 密钥。
     * @return 加密后的数据。
     */
    std::vector<uint8_t> encrypt(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                                 const std::vector<uint8_t> &key) const override;
    /*
     * @brief DES解密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @param key 密钥。
     * @return 解密后的数据。
     */
    std::vector<uint8_t> decrypt(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                                 const std::vector<uint8_t> &key) const override;
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
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @param key 密钥。
     * @return 加密后的数据。
     */
    std::vector<uint8_t> encrypt(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                                 const std::vector<uint8_t> &key) const override;
    /*
     * @brief AES解密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @param key 密钥。
     * @return 解密后的数据。
     */
    std::vector<uint8_t> decrypt(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                                 const std::vector<uint8_t> &key) const override;
};

// Block cipher mode

class block_cipher_mode
{
  public:
    virtual ~block_cipher_mode() = default;
    virtual std::vector<uint8_t> encrypt(std::vector<uint8_t>::const_iterator first,
                                         std::vector<uint8_t>::const_iterator last) const = 0;
    virtual std::vector<uint8_t> decrypt(std::vector<uint8_t>::const_iterator first,
                                         std::vector<uint8_t>::const_iterator last) const = 0;
};

// ECB
template <typename Cipher> class ECB : public block_cipher_mode
{
  public:
    /*
     * @brief ECB模式构造函数。
     * @param key 密钥。
     * @param cipher 块密码。
     */
    ECB(const std::vector<uint8_t> &key, const Cipher cipher) : key(key), cipher(cipher){};
    /*
     * @brief ECB模式加密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     */
    std::vector<uint8_t> encrypt(std::vector<uint8_t>::const_iterator first,
                                 std::vector<uint8_t>::const_iterator last) const override
    {
        return ecb(first, last, key, cipher.block_size(),
                   [this](auto first, auto last, auto key) { return cipher.encrypt(first, last, key); });
    }
    /*
     * @brief ECB模式解密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     */
    std::vector<uint8_t> decrypt(std::vector<uint8_t>::const_iterator first,
                                 std::vector<uint8_t>::const_iterator last) const override
    {
        return ecb(first, last, key, cipher.block_size(),
                   [this](auto first, auto last, auto key) { return cipher.decrypt(first, last, key); });
    }

  private:
    const std::vector<uint8_t> key;
    const Cipher cipher;

    template <typename Func>
    std::vector<uint8_t> ecb(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                             const std::vector<uint8_t> &key, const size_t block_size, Func cipher_func) const
    {
        using std::vector;
        if (std::distance(first, last) % block_size != 0)
        {
            throw std::invalid_argument("Input size must be a multiple of block size");
        }
        auto block_sz = block_size;
        vector<uint8_t> output(std::distance(first, last));
        for (auto i = first; i + block_sz <= last; i += block_sz)
        {
            auto block = cipher_func(i, i + block_sz, key);
            std::move(block.begin(), block.end(), output.begin() + (i - first));
        }
        return output;
    }
};

// CBC
template <typename Cipher> class CBC : public block_cipher_mode
{
  public:
    /*
     * @brief CBC模式构造函数。
     * @param key 密钥。
     * @param cipher 块密码。
     * @param z 初始向量。
     */
    CBC(const std::vector<uint8_t> &key, const Cipher cipher, const std::vector<uint8_t> &iv)
        : key(key), cipher(cipher), iv(iv)
    {
        if (iv.size() != cipher.block_size())
        {
            throw std::invalid_argument("IV size must be equal to block size");
        }
    };
    /*
     * @brief CBC模式加密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @return 加密后的数据。
     */
    std::vector<uint8_t> encrypt(std::vector<uint8_t>::const_iterator first,
                                 std::vector<uint8_t>::const_iterator last) const override
    {
        using std::vector;
        auto block_sz = cipher.block_size();
        if (std::distance(first, last) % block_sz)
        {
            throw std::invalid_argument("Input size must be a multiple of block size");
        }
        vector<uint8_t> output(std::distance(first, last));
        for (auto i = first; i + block_sz <= last; i += block_sz)
        {
            vector<uint8_t> block(block_sz);
            auto output_it = output.begin() + (i - first);
            if (i == first)
            {
                std::transform(i, i + block_sz, iv.begin(), block.begin(), std::bit_xor<uint8_t>());
            }
            else
            {
                std::transform(i, i + block_sz, output_it - block_sz, block.begin(), std::bit_xor<uint8_t>());
            }
            block = cipher.encrypt(block.begin(), block.end(), key);
            std::move(block.begin(), block.end(), output_it);
        }
        return output;
    }
    /*
     * @brief CBC模式解密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @return 解密后的数据。
     */
    std::vector<uint8_t> decrypt(std::vector<uint8_t>::const_iterator first,
                                 std::vector<uint8_t>::const_iterator last) const override
    {
        using std::vector;
        auto block_sz = cipher.block_size();
        if (std::distance(first, last) % block_sz)
        {
            throw std::invalid_argument("Input size must be a multiple of block size");
        }
        vector<uint8_t> output(std::distance(first, last));
        for (auto i = first; i + block_sz <= last; i += block_sz)
        {
            auto block = cipher.decrypt(i, i + block_sz, key);
            auto output_it = output.begin() + (i - first);
            if (i == first)
            {
                std::transform(block.begin(), block.end(), iv.begin(), output_it, std::bit_xor<uint8_t>());
            }
            else
            {
                std::transform(block.begin(), block.end(), i - block_sz, output_it, std::bit_xor<uint8_t>());
            }
        }
        return output;
    }

  private:
    const std::vector<uint8_t> key;
    const Cipher cipher;
    const std::vector<uint8_t> iv;
};

// OFB
class OFB : public block_cipher_mode
{
  public:
    /*
     * @brief OFB模式构造函数。
     * @param key 密钥。
     * @param cipher 块密码。
     * @param iv 初始向量。
     */
    OFB(const std::vector<uint8_t> &key, const block_cipher &cipher, const std::vector<uint8_t> &iv);
    /*
     * @brief OFB模式加密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @return 加密后的数据。
     */
    std::vector<uint8_t> encrypt(std::vector<uint8_t>::const_iterator first,
                                 std::vector<uint8_t>::const_iterator last) const override;
    /*
     * @brief OFB模式解密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @return 解密后的数据。
     */
    std::vector<uint8_t> decrypt(std::vector<uint8_t>::const_iterator first,
                                 std::vector<uint8_t>::const_iterator last) const override;

  private:
    const std::vector<uint8_t> key;
    const focalors::block_cipher &cipher;
    const std::vector<uint8_t> iv;
};

// CFB
class CFB : public block_cipher_mode
{
  public:
    /*
     * @brief CFB模式构造函数。
     * @param key 密钥。
     * @param cipher 块密码。
     * @param iv 初始向量。
     */
    CFB(const std::vector<uint8_t> &key, const block_cipher &cipher, const std::vector<uint8_t> &iv);
    /*
     * @brief CFB模式加密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @return 加密后的数据。
     */
    std::vector<uint8_t> encrypt(std::vector<uint8_t>::const_iterator first,
                                 std::vector<uint8_t>::const_iterator last) const override;
    /*
     * @brief CFB模式解密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @return 解密后的数据。
     */
    std::vector<uint8_t> decrypt(std::vector<uint8_t>::const_iterator first,
                                 std::vector<uint8_t>::const_iterator last) const override;

  private:
    const std::vector<uint8_t> key;
    const focalors::block_cipher &cipher;
    const std::vector<uint8_t> iv;
};

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
} // namespace focalors
#endif // FOCALORS_H