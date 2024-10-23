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
void des_encrypt(crypt::bitset<64> &ciphertext, const crypt::bitset<64> &plaintext, const crypt::bitset<64> &key);
void des_decrypt(crypt::bitset<64> &plaintext, const crypt::bitset<64> &ciphertext, const crypt::bitset<64> &key);
template <typename T>
void ecb(std::string &output_string, const std::string &input_string, const T &key,
         std::function<void(T &output, const T &input, const T &key)> crypt_func)
{
    output_string.clear();
    std::vector<T> input, output;
    group_mode::split_input(input, input_string);
    output.resize(input.size());
    for (auto i = input.begin(), j = output.begin(); i != input.end() && j != output.end(); i++, j++)
    {
        crypt_func(*j, *i, key);
    }
    group_mode::merge_output(output_string, output);
}

template <typename T>
void cbc(std::string &output_string, const std::string &input_string, const T &key, const T &z, const bool &decrypt,
         std::function<void(T &output, const T &input, const T &key)> crypt_func)
{
    output_string.clear();
    std::vector<T> input, output;
    group_mode::split_input(input, input_string);
    output.resize(input.size());
    for (auto i = input.begin(), j = output.begin(); i != input.end() && j != output.end(); i++, j++)
    {
        if (decrypt)
        {
            crypt_func(*j, *i, key);
            if (i == input.begin())
            {
                *j ^= z;
            }
            else
            {
                *j ^= *(i - 1);
            }
        }
        else
        {
            if (i == input.begin())
            {
                T temp = *i;
                temp ^= z;
                crypt_func(*j, temp, key);
            }
            else
            {
                T temp = T((*i) ^ (*(j - 1)));
                crypt_func(*j, temp, key);
            }
        }
    }
    group_mode::merge_output(output_string, output);
}

template <typename T>
void ofb(std::string &output_string, const std::string &input_string, const T &key, const T &seed, const size_t &s,
         std::function<void(T &output, const T &input, const T &key)> crypt_func)
{
    output_string.clear();
    if (s > T().size() || s < 1)
    {
        throw std::invalid_argument("Invalid s");
    }
    T r, e;
    r = seed;
    std::vector<std::string> splited_input_string;
    group_mode::split_input_stream(splited_input_string, input_string, s);
    for (auto i = splited_input_string.begin(); i != splited_input_string.end(); i++)
    {
        crypt_func(e, r, key);
        T stream_out = e;
        stream_out ^= T(*i);
        stream_out &= T(std::string(i->size(), '1'));
        *i = stream_out.to_string().substr(stream_out.size() - i->size(), i->size());
        r <<= s;
        r |= e & T(std::string(s, '1'));
    }
    group_mode::merge_output_stream(output_string, splited_input_string);
}

template <typename T>
void cfb(std::string &output_string, const std::string &input_string, const T &key, const T &seed, const size_t &s,
         const bool &decrypt, std::function<void(T &output, const T &input, const T &key)> crypt_func)
{
    output_string.clear();
    if (s > T().size() || s < 1)
    {
        throw std::invalid_argument("Invalid s");
    }
    T r, e;
    r = seed;
    std::vector<std::string> splited_input_string;
    group_mode::split_input_stream(splited_input_string, input_string, s);
    for (auto i = splited_input_string.begin(); i != splited_input_string.end(); i++)
    {
        crypt_func(e, r, key);
        T stream_out = e;
        stream_out ^= T(*i);
        stream_out &= T(std::string(i->size(), '1'));
        if (i + 1 == splited_input_string.end())
        {
            *i = stream_out.to_string().substr(stream_out.size() - i->size(), i->size());
            break;
        }
        r <<= s;
        if (decrypt)
        {
            r |= T(*i);
        }
        else
        {
            r |= stream_out;
        }
        *i = stream_out.to_string().substr(stream_out.size() - i->size(), i->size());
    }
    group_mode::merge_output_stream(output_string, splited_input_string);
}
} // namespace crypt

#endif // CRYPT_H