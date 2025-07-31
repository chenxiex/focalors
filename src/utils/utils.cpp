#include "utils.h"
#include <bitset>
#include <iomanip>
#include <ios>
#include <sstream>

namespace focalors
{
using namespace std;

vector<uint8_t> binary_to_bytes(const string &binary)
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
string binary_to_hex(const string &binary)
{
    stringstream ss;
    for (size_t i = 0; i < binary.size(); i += 4)
    {
        std::bitset<4> b(binary.substr(i, 4));
        ss << std::hex << b.to_ulong();
    }
    return ss.str();
}
string hex_to_binary(const string &hex)
{
    stringstream ss;
    for (size_t i = 0; i < hex.size(); ++i)
    {
        unsigned int n;
        stringstream(hex.substr(i, 1)) >> std::hex >> n;
        ss << std::bitset<4>(n);
    }
    return ss.str();
}
std::vector<uint8_t> hex_to_bytes(const std::string &hex)
{
    vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        bytes.push_back(stoul(hex.substr(i, 2), nullptr, 16));
    }
    return bytes;
}
std::string bytes_to_hex(const std::vector<uint8_t> &bytes)
{
    stringstream ss;
    ss << hex << setfill('0');
    for (auto byte : bytes)
    {
        ss << setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}
} // namespace focalors