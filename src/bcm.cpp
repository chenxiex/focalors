#include "bcm.h"
#include <cmath>
#include <string>
#include <vector>
using std::string;
using std::vector;

namespace bcm
{
void split_input_stream(vector<string> &text, const string &input, const int s)
{
    text.clear();
    for (size_t i = 1; i <= input.length() / s; i++)
    {
        text.push_back(input.substr(input.length() - i * s, s));
    }
    if (input.length() % s != 0)
    {
        text.push_back(input.substr(0, input.length() % s));
    }
}
void merge_output_stream(string &output, const vector<string> &text)
{
    output.clear();
    for (auto i = text.rbegin(); i != text.rend(); i++)
    {
        output += *i;
    }
}
} // namespace bcm
