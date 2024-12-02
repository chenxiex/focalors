#pragma once
#ifndef bcm_IMPL_H
#define bcm_IMPL_H
#include "bcm.h"
#include "crypt.h"
namespace bcm
{
template <typename T> void split_input(std::vector<T> &text, const std::string &input)
{
    int length = T().size();
    if (input.size() % length != 0)
    {
        throw std::invalid_argument("Invalid input length");
    }
    text.clear();
    for (size_t i = 0; i < input.size(); i += length)
    {
        text.emplace_back(input.substr(i, length));
    }
}
template <typename T> void merge_output(std::string &output, const std::vector<T> &text)
{
    output.clear();
    for (auto i = text.begin(); i != text.end(); i++)
    {
        output += i->to_string();
    }
}
} // namespace bcm

namespace crypt
{
template <typename BT, typename KT>
void ecb(std::string &output_string, const std::string &input_string, const KT &key,
         std::function<void(BT &output, const BT &input, const KT &key)> crypt_func)
{
    output_string.clear();
    std::vector<BT> input, output;
    bcm::split_input(input, input_string);
    output.resize(input.size());
    for (auto i = input.begin(), j = output.begin(); i != input.end() && j != output.end(); i++, j++)
    {
        crypt_func(*j, *i, key);
    }
    bcm::merge_output(output_string, output);
}

template <typename BT, typename KT>
void ecb_stream_cipher_padding(std::string &output_string, const std::string &input_string, const KT &key,
                               const BT &seed, const bool &decrypt,
                               std::function<void(BT &output, const BT &input, const KT &key)> crypt_func,
                               std::function<void(BT &output, const BT &input, const KT &key)> encrypt_func)
{
    output_string.clear();
    std::vector<BT> input, output;
    size_t padding = 0;
    if (input_string.size() % BT().size() != 0)
    {
        std::string padded_input_string = input_string;
        while (padded_input_string.size() % BT().size() != 0)
        {
            padded_input_string += "0";
            padding++;
        }
        bcm::split_input(input, padded_input_string);
    }
    else
    {
        bcm::split_input(input, input_string);
    }
    output.resize(input.size());
    for (auto i = input.begin(), j = output.begin();
         (i + 1 < input.end() && padding) || (i < input.end() && !padding); i++, j++)
    {
        crypt_func(*j, *i, key);
    }
    if (input.size() > 0 && padding)
    {
        if (input.size() == 1)
        {
            encrypt_func(*output.begin(), seed, key);
            *output.begin() ^= *input.begin();
        }
        else
        {
            if (!decrypt)
            {
                encrypt_func(*output.rbegin(), *(output.rbegin() + 1), key);
                *output.rbegin() ^= *input.rbegin();
            }
            else
            {
                encrypt_func(*output.rbegin(), *(input.rbegin() + 1), key);
                *output.rbegin() ^= *input.rbegin();
            }
        }
    }
    bcm::merge_output(output_string, output);
    if (padding)
    {
        output_string = output_string.substr(0, output_string.size() - padding);
    }
}

template <typename BT, typename KT>
void cbc(std::string &output_string, const std::string &input_string, const KT &key, const BT &z, const bool &decrypt,
         std::function<void(BT &output, const BT &input, const KT &key)> crypt_func)
{
    output_string.clear();
    std::vector<BT> input, output;
    bcm::split_input(input, input_string);
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
                BT temp = *i;
                temp ^= z;
                crypt_func(*j, temp, key);
            }
            else
            {
                BT temp = BT((*i) ^ (*(j - 1)));
                crypt_func(*j, temp, key);
            }
        }
    }
    bcm::merge_output(output_string, output);
}

template <typename BT, typename KT>
void ofb(std::string &output_string, const std::string &input_string, const KT &key, const BT &seed, const size_t &s,
         std::function<void(BT &output, const BT &input, const KT &key)> crypt_func)
{
    output_string.clear();
    if (s > BT().size() || s < 1)
    {
        throw std::invalid_argument("Invalid size");
    }
    BT r, e;
    r = seed;
    std::vector<std::string> splited_input_string;
    bcm::split_input_stream(splited_input_string, input_string, s);
    for (auto i = splited_input_string.begin(); i != splited_input_string.end(); i++)
    {
        crypt_func(e, r, key);
        BT stream_out = e;
        stream_out ^= BT(*i);
        stream_out &= BT(std::string(i->size(), '1'));
        *i = stream_out.to_string().substr(stream_out.size() - i->size(), i->size());
        r <<= s;
        r |= e & BT(std::string(s, '1'));
    }
    bcm::merge_output_stream(output_string, splited_input_string);
}

template <typename BT, typename KT>
void cfb(std::string &output_string, const std::string &input_string, const KT &key, const BT &seed, const size_t &s,
         const bool &decrypt, std::function<void(BT &output, const BT &input, const KT &key)> crypt_func)
{
    output_string.clear();
    if (s > BT().size() || s < 1)
    {
        throw std::invalid_argument("Invalid size");
    }
    BT r, e;
    r = seed;
    std::vector<std::string> splited_input_string;
    bcm::split_input_stream(splited_input_string, input_string, s);
    for (auto i = splited_input_string.begin(); i != splited_input_string.end(); i++)
    {
        crypt_func(e, r, key);
        BT stream_out = e;
        stream_out ^= BT(*i);
        stream_out &= BT(std::string(i->size(), '1'));
        if (i + 1 == splited_input_string.end())
        {
            *i = stream_out.to_string().substr(stream_out.size() - i->size(), i->size());
            break;
        }
        r <<= s;
        if (decrypt)
        {
            r |= BT(*i);
        }
        else
        {
            r |= stream_out;
        }
        *i = stream_out.to_string().substr(stream_out.size() - i->size(), i->size());
    }
    bcm::merge_output_stream(output_string, splited_input_string);
}
template <typename BT, typename KT>
void x_cbc(std::string &output_string, const std::string &input_string, const KT &k1, const BT &k2, const BT &k3,
           const BT &z, const bool &decrypt, const size_t padding,
           std::function<void(BT &output, const BT &input, const KT &key)> crypt_func)
{
    output_string.clear();
    std::vector<BT> input, output;
    if (padding && !decrypt)
    {
        std::string input_string_padded = input_string;
        input_string_padded += "1" + std::string(padding - 1, '0');
        bcm::split_input(input, input_string_padded);
    }
    else
    {
        bcm::split_input(input, input_string);
    }
    output.resize(input.size());
    for (auto i = input.begin(), j = output.begin(); i != input.end() && j != output.end(); i++, j++)
    {
        if (i + 1 != input.end() && j + 1 != output.end())
        {
            if (decrypt)
            {
                crypt_func(*j, *i, k1);
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
                    BT temp = *i;
                    temp ^= z;
                    crypt_func(*j, temp, k1);
                }
                else
                {
                    BT temp = BT((*i) ^ (*(j - 1)));
                    crypt_func(*j, temp, k1);
                }
            }
        }
        else
        {
            auto &key = padding ? k3 : k2;
            if (decrypt)
            {
                crypt_func(*j, *i, k1);
                *j ^= *(i - 1) ^ key;
            }
            else
            {
                BT temp = BT((*i) ^ (*(j - 1)) ^ key);
                crypt_func(*j, temp, k1);
            }
        }
    }
    bcm::merge_output(output_string, output);
    if (padding && decrypt)
    {
        output_string = output_string.substr(0, output_string.size() - padding);
    }
}
template <typename BT, typename KT>
void ctr(std::string &output_string, const std::string &input_string, const KT &key, const std::string &seed_string,
         std::function<void(BT &output, const BT &input, const KT &key)> crypt_func)
{
    output_string.clear();
    if (seed_string.size() % BT().size() != 0 || seed_string.size() < input_string.size())
    {
        throw std::invalid_argument("Invalid seed length");
    }
    std::vector<BT> seed;
    bcm::split_input(seed, seed_string);
    std::vector<BT> input, output;
    size_t padding = 0;
    if (input_string.size() % BT().size() != 0)
    {
        std::string padded_input_string = input_string;
        while (padded_input_string.size() % BT().size() != 0)
        {
            padded_input_string += "0";
            padding++;
        }
        bcm::split_input(input, padded_input_string);
    }
    else
    {
        bcm::split_input(input, input_string);
    }
    output.resize(input.size());
    for (auto i = input.begin(), j = output.begin(), k = seed.begin(); i != input.end(); i++, j++, k++)
    {
        BT o;
        crypt_func(o, *k, key);
        *j = *i ^ o;
    }
    bcm::merge_output(output_string, output);
    if (padding)
    {
        output_string = output_string.substr(0, output_string.size() - padding);
    }
}
} // namespace crypt
#endif