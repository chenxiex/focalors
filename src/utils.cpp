#include "focalors.h"

namespace focalors
{
using namespace std;

vector<uint8_t> binary_to_bytes(const std::string &binary)
{
    vector<uint8_t> bytes;
    for (size_t i = 0; i < binary.size(); i += 8)
    {
        bytes.push_back(stoul(binary.substr(i, 8), nullptr, 2));
    }
    return bytes;
}
string bytes_to_binary(const vector<uint8_t> &bytes)
{
    string binary;
    for (auto byte : bytes)
    {
        binary += bitset<8>(byte).to_string();
    }
    return binary;
}
} // namespace focalors