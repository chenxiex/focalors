#pragma once
#ifndef FOCALORS_H
#define FOCALORS_H
#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace focalors
{
// Block cipher
template <typename Cipher>
concept BlockCipher = requires(Cipher c, std::vector<uint8_t>::const_iterator first,
                               std::vector<uint8_t>::const_iterator last, const std::vector<uint8_t> &key)
{
    {
        c.block_size()
        } -> std::convertible_to<size_t>;
    {
        c.encrypt(first, last, key)
        } -> std::same_as<std::vector<uint8_t>>;
    {
        c.decrypt(first, last, key)
        } -> std::same_as<std::vector<uint8_t>>;
};

// DES
class DES
{
  public:
    /*
     * @brief 获取块大小。
     * @return 块大小。
     */
    constexpr size_t block_size() const noexcept
    {
        return 8;
    }
    /*
     * @brief DES加密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @param key 密钥。
     * @return 加密后的数据。
     */
    std::vector<uint8_t> encrypt(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                                 const std::vector<uint8_t> &key) const;
    /*
     * @brief DES解密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @param key 密钥。
     * @return 解密后的数据。
     */
    std::vector<uint8_t> decrypt(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                                 const std::vector<uint8_t> &key) const;
};

// AES
class AES
{
  public:
    /*
     * @brief 获取块大小。
     * @return 块大小。
     */
    constexpr size_t block_size() const noexcept
    {
        return 16;
    }
    /*
     * @brief AES加密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @param key 密钥。
     * @return 加密后的数据。
     */
    std::vector<uint8_t> encrypt(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                                 const std::vector<uint8_t> &key) const;
    /*
     * @brief AES解密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @param key 密钥。
     * @return 解密后的数据。
     */
    std::vector<uint8_t> decrypt(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                                 const std::vector<uint8_t> &key) const;
};

// Block cipher mode

// ECB
template <BlockCipher Cipher> class ECB
{
  public:
    /*
     * @brief ECB模式构造函数。
     * @param key 密钥。
     * @param cipher 块密码。
     */
    ECB(const std::vector<uint8_t> &key) : key(key), cipher(Cipher())
    {
    }
    /*
     * @brief ECB模式加密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     */
    std::vector<uint8_t> encrypt(std::vector<uint8_t>::const_iterator first,
                                 std::vector<uint8_t>::const_iterator last) const
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
                                 std::vector<uint8_t>::const_iterator last) const
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
template <BlockCipher Cipher> class CBC
{
  public:
    /*
     * @brief CBC模式构造函数。
     * @param key 密钥。
     * @param cipher 块密码。
     * @param z 初始向量。
     */
    CBC(const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv) : key(key), cipher(Cipher()), iv(iv)
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
                                 std::vector<uint8_t>::const_iterator last) const
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
                                 std::vector<uint8_t>::const_iterator last) const
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
template <BlockCipher Cipher> class OFB
{
  public:
    /*
     * @brief OFB模式构造函数。
     * @param key 密钥。
     * @param cipher 块密码。
     * @param iv 初始向量。
     */
    OFB(const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv) : key(key), cipher(Cipher()), iv(iv)
    {
        if (iv.size() != cipher.block_size())
        {
            throw std::invalid_argument("IV size must be equal to block size.");
        }
    }
    /*
     * @brief OFB模式加密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @return 加密后的数据。
     */
    std::vector<uint8_t> encrypt(std::vector<uint8_t>::const_iterator first,
                                 std::vector<uint8_t>::const_iterator last) const
    {
        const size_t length = std::distance(first, last);
        std::vector<uint8_t> r(iv.begin(), iv.end());
        std::vector<uint8_t> result(length);
        const auto block_sz = cipher.block_size();
        auto result_it = result.begin();
        auto remainning = length;
        for (auto i = first; i < last;)
        {
            r = cipher.encrypt(r.begin(), r.end(), key);
            auto step = std::min(remainning, block_sz);
            result_it = std::transform(i, std::next(i, step), r.begin(), result_it, std::bit_xor<uint8_t>());
            std::advance(i, step);
            remainning -= step;
        }
        return result;
    }
    /*
     * @brief OFB模式解密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @return 解密后的数据。
     */
    std::vector<uint8_t> decrypt(std::vector<uint8_t>::const_iterator first,
                                 std::vector<uint8_t>::const_iterator last) const
    {
        return encrypt(first, last);
    }

  private:
    const std::vector<uint8_t> key;
    const Cipher cipher;
    const std::vector<uint8_t> iv;
};

// CFB
template <BlockCipher Cipher> class CFB
{
  public:
    /*
     * @brief CFB模式构造函数。
     * @param key 密钥。
     * @param cipher 块密码。
     * @param iv 初始向量。
     */
    CFB(const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv) : key(key), cipher(Cipher()), iv(iv)
    {
        if (iv.size() != cipher.block_size())
        {
            throw std::invalid_argument("IV size must be equal to block size.");
        }
    }
    /*
     * @brief CFB模式加密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @return 加密后的数据。
     */
    std::vector<uint8_t> encrypt(std::vector<uint8_t>::const_iterator first,
                                 std::vector<uint8_t>::const_iterator last) const
    {
        return process<true>(first, last, key, iv, cipher);
    }
    /*
     * @brief CFB模式解密。
     * @param first 输入数据的起始迭代器。
     * @param last 输入数据的结束迭代器。
     * @return 解密后的数据。
     */
    std::vector<uint8_t> decrypt(std::vector<uint8_t>::const_iterator first,
                                 std::vector<uint8_t>::const_iterator last) const
    {
        return process<false>(first, last, key, iv, cipher);
    }

  private:
    const std::vector<uint8_t> key;
    const Cipher cipher;
    const std::vector<uint8_t> iv;

    template <bool encrypt>
    std::vector<uint8_t> process(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                                 const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv,
                                 const Cipher &cipher) const
    {
        const size_t length = std::distance(first, last);
        std::vector<uint8_t> r(iv.begin(), iv.end());
        std::vector<uint8_t> result(length);
        const auto block_sz = cipher.block_size();
        auto result_it = result.begin();
        auto remainning = length;
        for (auto i = first; i < last;)
        {
            auto step = std::min(remainning, block_sz);
            if constexpr (encrypt)
            {
                r = cipher.encrypt(r.begin(), r.end(), key);
                std::transform(i, std::next(i, step), r.begin(), result_it, std::bit_xor<uint8_t>());
                if (step == block_sz)
                {
                    std::copy(result_it, std::next(result_it, block_sz), r.begin());
                }
            }
            else
            {
                auto e = cipher.encrypt(r.begin(), r.end(), key);
                if (step == block_sz)
                {
                    std::copy(i, std::next(i, block_sz), r.begin());
                }
                std::transform(i, std::next(i, step), e.begin(), result_it, std::bit_xor<uint8_t>());
            }
            std::advance(i, step);
            std::advance(result_it, step);
            remainning -= step;
        }
        return result;
    }
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