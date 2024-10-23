#ifndef GROUP_MODE_H
#define GROUP_MODE_H
#include <stdexcept>
#include <string>
#include <vector>
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
#endif