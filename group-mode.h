#ifndef GROUP_MODE_H
#define GROUP_MODE_H
#include <stdexcept>
#include <string>
#include <vector>
#include <functional>
namespace group_mode
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
        text.push_back(T(input.substr(i, length)));
    }
}

void split_input_stream(std::vector<std::string> &text, const std::string &input, const int s);

template <typename T> void merge_output(std::string &output, const std::vector<T> &text)
{
    output.clear();
    for (auto i = text.begin(); i != text.end(); i++)
    {
        output += i->to_string();
    }
}

void merge_output_stream(std::string &output, const std::vector<std::string> &text);
} // namespace group_mode

namespace crypt
{
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
#endif