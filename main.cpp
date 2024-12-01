#include "crypt.h"
#include <cstring>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <variant>
using crypt::bitset;
using std::cout;
using std::endl;
using std::string;
using std::variant;
std::unordered_map<string, string> args = {
    {"decrypt", "false"}, {"algorithm", "des"}, {"bcm", "ecb"}, {"encoding", "binary"}};
void print_help()
{
    // 用中文打印Unix风格的帮助信息
    cout << "用法: crypt [选项]... [输入]\n"
            "加密或解密输入\n"
            "\n"
            "  -h, --help          显示此帮助信息并退出\n"
            "  -k, --key=KEY       使用KEY作为密钥\n"
            "  -d, --decrypt       解密模式\n"
            "  -a, --algorithm=ALG 使用ALG算法\n"
            "  -m, --bcm=M         使用M分组模式\n"
            "  -e, --encoding=ENC  使用ENC编码\n"
            "  -f, --file=FILE     从FILE读取输入\n"
            "  -s, --seed=SEED     使用SEED作为初始向量\n"
            "  -z, --size=SIZE     "
            "当使用CFB或OFB分组模式时，SIZE是每次参与异或的明文长度；当使用X_CBC分组模式时，SIZE是填充数据长度。\n"
            "  -K, --key-file=FILE 从FILE读取密钥\n"
            "\n";
    return;
}
string ascii_to_binary_string(const string &input)
{
    std::stringstream ss;
    for (char c : input)
    {
        ss << std::bitset<sizeof(c) * 8>(c);
    }
    return ss.str();
}
string binary_to_ascii_string(const string &input)
{
    std::stringstream ss;
    for (size_t i = 0; i < input.size(); i += 8)
    {
        std::bitset<8> b(input.substr(i, 8));
        ss << static_cast<char>(b.to_ulong());
    }
    return ss.str();
}
std::string hex_to_binary_string(const std::string &hex)
{
    std::stringstream ss;
    for (size_t i = 0; i < hex.size(); ++i)
    {
        unsigned int n;
        std::stringstream(hex.substr(i, 1)) >> std::hex >> n;
        ss << std::bitset<4>(n);
    }
    return ss.str();
}
std::string binary_to_hex_string(const std::string &binary)
{
    std::stringstream ss;
    for (size_t i = 0; i < binary.size(); i += 4)
    {
        std::bitset<4> b(binary.substr(i, 4));
        ss << std::hex << b.to_ulong();
    }
    return ss.str();
}
template <size_t KN>
void aes_ecb(string &output, const string &input, const variant<bitset<128>, bitset<192>, bitset<256>> &key,
             const bool &decrypt)
{
    crypt::ecb(output, input, std::get<bitset<KN>>(key),
               std::function(decrypt ? crypt::aes_decrypt<128, KN> : crypt::aes_encrypt<128, KN>));
}
template <size_t KN>
void aes_cbc(string &output, const string &input, const variant<bitset<128>, bitset<192>, bitset<256>> &key,
             const bitset<128> &seed, const bool &decrypt)
{
    crypt::cbc<bitset<128>, bitset<KN>>(
        output, input, std::get<bitset<KN>>(key), seed, decrypt,
        std::function(decrypt ? crypt::aes_decrypt<128, KN> : crypt::aes_encrypt<128, KN>));
}
template <size_t KN>
void aes_ofb(string &output, const string &input, const variant<bitset<128>, bitset<192>, bitset<256>> &key,
             const bitset<128> &seed, const size_t &s)
{
    crypt::ofb(output, input, std::get<bitset<KN>>(key), seed, s, std::function(crypt::aes_encrypt<128, KN>));
}
template <size_t KN>
void aes_cfb(string &output, const string &input, const variant<bitset<128>, bitset<192>, bitset<256>> &key,
             const bitset<128> &seed, const size_t &s, const bool &decrypt)
{
    crypt::cfb(output, input, std::get<bitset<KN>>(key), seed, s, decrypt, std::function(crypt::aes_encrypt<128, KN>));
}
template <size_t KN>
void aes_x_cbc(string &output, const string &input, const variant<bitset<128>, bitset<192>, bitset<256>> &k1,
               const bitset<128> &k2, const bitset<128> &k3, const bitset<128> &z, const bool &decrypt,
               const size_t padding)
{
    crypt::x_cbc(output, input, std::get<bitset<KN>>(k1), k2, k3, z, decrypt, padding,
                 std::function(decrypt ? crypt::aes_decrypt<128, KN> : crypt::aes_encrypt<128, KN>));
}
int main(int argc, char *argv[])
{
    // 解析参数
    struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},       {"key", required_argument, NULL, 'k'},
        {"decrypt", no_argument, NULL, 'd'},    {"algorithm", required_argument, NULL, 'a'},
        {"bcm", required_argument, NULL, 'm'},  {"encoding", no_argument, NULL, 'e'},
        {"file", required_argument, NULL, 'f'}, {"seed", required_argument, NULL, 's'},
        {"size", required_argument, NULL, 'z'}, {"key-file", required_argument, NULL, 'K'},
    };
    {
        int opt;
        while ((opt = getopt_long(argc, argv, "hk:da:m:e:f:s:z:K:", long_options, NULL)) != -1)
        {
            switch (opt)
            {
            case 'h':
                print_help();
                break;
            case 'k':
                args["key"] = optarg;
                break;
            case 'd':
                args["decrypt"] = "true";
                break;
            case 'a':
                args["algorithm"] = optarg;
                break;
            case 'm':
                args["bcm"] = optarg;
                break;
            case 'e':
                args["encoding"] = optarg;
                break;
            case 'f':
                args["file"] = optarg;
                break;
            case 's':
                args["seed"] = optarg;
                break;
            case 'z':
                args["size"] = optarg;
                break;
            case 'K':
                args["key-file"] = optarg;
                break;
            default:
                print_help();
                break;
            }
        }

        if (optind < argc)
        {
            if (args.count("file") != 0)
            {
                throw std::invalid_argument("Too many inputs");
            }
            args["input"] = argv[optind];
        }
        else if (args.count("file") == 0)
        {
            throw std::invalid_argument("No input");
        }
        else
        {
            std::ifstream file(args["file"]);
            file >> args["input"];
            file.close();
        }

        if (args.count("key") == 0)
        {
            if (args.count("key-file") == 0)
            {
                throw std::invalid_argument("No key");
            }
            else
            {
                std::ifstream file(args["key-file"]);
                file >> args["key"];
                file.close();
            }
        }

        if (args["encoding"] == "ascii")
        {
            args["input"] = ascii_to_binary_string(args["input"]);
        }
        else if (args["encoding"] == "hex")
        {
            args["input"] = hex_to_binary_string(args["input"]);
            args["key"] = hex_to_binary_string(args["key"]);
            args["seed"] = hex_to_binary_string(args["seed"]);
        }

        if (args["decrypt"] != "true" && args["decrypt"] != "false")
        {
            throw std::invalid_argument("Argument decrypt must be true or false");
        }
    }

    // 执行算法
    string output;
    if (args["algorithm"] == "des")
    {
        if (args["bcm"] == "ecb")
        {
            if (args["key"].size() != 64)
            {
                throw std::invalid_argument("Invalid key size");
            }
            crypt::ecb(output, args["input"], bitset<64>(args["key"]),
                       std::function(args["decrypt"] == "true" ? crypt::des_decrypt : crypt::des_encrypt));
        }
        else if (args["bcm"] == "cbc")
        {
            if (args["key"].size() != 64)
            {
                throw std::invalid_argument("Invalid key size");
            }
            if (args["seed"].size() != 64)
            {
                throw std::invalid_argument("Invalid seed size");
            }
            crypt::cbc<bitset<64>, bitset<64>>(
                output, args["input"], bitset<64>(args["key"]), bitset<64>(args["seed"]), args["decrypt"] == "true",
                std::function(args["decrypt"] == "true" ? crypt::des_decrypt : crypt::des_encrypt));
        }
        else if (args["bcm"] == "ofb")
        {
            if (args["key"].size() != 64)
            {
                throw std::invalid_argument("Invalid key size");
            }
            if (args["seed"].size() != 64)
            {
                throw std::invalid_argument("Invalid seed size");
            }
            if (args.count("size") == 0)
            {
                throw std::invalid_argument("No size");
            }
            crypt::ofb(output, args["input"], bitset<64>(args["key"]), bitset<64>(args["seed"]),
                       std::stoi(args["size"]), std::function(crypt::des_encrypt));
        }
        else if (args["bcm"] == "cfb")
        {
            if (args["key"].size() != 64)
            {
                throw std::invalid_argument("Invalid key size");
            }
            if (args["seed"].size() != 64)
            {
                throw std::invalid_argument("Invalid seed size");
            }
            if (args.count("size") == 0)
            {
                throw std::invalid_argument("No size");
            }
            crypt::cfb(output, args["input"], bitset<64>(args["key"]), bitset<64>(args["seed"]),
                       std::stoi(args["size"]), args["decrypt"] == "true", std::function(crypt::des_encrypt));
        }
        else if (args["bcm"] == "x_cbc")
        {
            if (args["key"].size() != 192)
            {
                throw std::invalid_argument("Invalid key size");
            }
            if (args["seed"].size() != 64)
            {
                throw std::invalid_argument("Invalid seed size");
            }
            if (args.count("size") == 0)
            {
                throw std::invalid_argument("No size");
            }
            bitset<64> k1(args["key"].substr(0, 64)), k2(args["key"].substr(64, 64)), k3(args["key"].substr(128, 64));
            crypt::x_cbc(output, args["input"], k1, k2, k3, bitset<64>(args["seed"]), args["decrypt"] == "true",
                         stoi(args["size"]),
                         std::function(args["decrypt"] == "true" ? crypt::des_decrypt : crypt::des_encrypt));
        }
        else
        {
            throw std::invalid_argument("Invalid group mode");
        }
    }
    else if (args["algorithm"] == "aes")
    {
        variant<bitset<128>, bitset<192>, bitset<256>> key;
        bitset<128> k2, k3;
        if (args["bcm"] == "x_cbc")
        {
            switch (args["key"].size())
            {
            case 384:
                key = bitset<128>(args["key"].substr(0, 128));
                k2 = bitset<128>(args["key"].substr(128, 128));
                k3 = bitset<128>(args["key"].substr(256, 128));
                break;
            case 448:
                key = bitset<192>(args["key"].substr(0, 192));
                k2 = bitset<128>(args["key"].substr(192, 128));
                k3 = bitset<128>(args["key"].substr(320, 128));
                break;
            case 512:
                key = bitset<256>(args["key"].substr(0, 256));
                k2 = bitset<128>(args["key"].substr(256, 128));
                k3 = bitset<128>(args["key"].substr(384, 128));
                break;
            default:
                throw std::invalid_argument("Invalid key size");
            }
        }
        else
        {
            switch (args["key"].size())
            {
            case 128:
                key = bitset<128>(args["key"]);
                break;
            case 192:
                key = bitset<192>(args["key"]);
                break;
            case 256:
                key = bitset<256>(args["key"]);
                break;
            default:
                throw std::invalid_argument("Invalid key size");
            }
        }

        if (args["bcm"] == "ecb")
        {
            switch (args["key"].size())
            {
            case 128:
                aes_ecb<128>(output, args["input"], key, args["decrypt"] == "true");
                break;
            case 192:
                aes_ecb<192>(output, args["input"], key, args["decrypt"] == "true");
                break;
            case 256:
                aes_ecb<256>(output, args["input"], key, args["decrypt"] == "true");
                break;
            }
        }
        else if (args["bcm"] == "cbc")
        {
            if (args["seed"].size() != 128)
            {
                throw std::invalid_argument("Invalid seed size");
            }
            switch (args["key"].size())
            {
            case 128:
                aes_cbc<128>(output, args["input"], key, bitset<128>(args["seed"]), args["decrypt"] == "true");
                break;
            case 192:
                aes_cbc<192>(output, args["input"], key, bitset<128>(args["seed"]), args["decrypt"] == "true");
                break;
            case 256:
                aes_cbc<256>(output, args["input"], key, bitset<128>(args["seed"]), args["decrypt"] == "true");
                break;
            }
        }
        else if (args["bcm"] == "ofb")
        {
            if (args["seed"].size() != 128)
            {
                throw std::invalid_argument("Invalid seed size");
            }
            if (args.count("size") == 0)
            {
                throw std::invalid_argument("No size");
            }
            switch (args["key"].size())
            {
            case 128:
                aes_ofb<128>(output, args["input"], key, bitset<128>(args["seed"]), std::stoi(args["size"]));
                break;
            case 192:
                aes_ofb<192>(output, args["input"], key, bitset<128>(args["seed"]), std::stoi(args["size"]));
                break;
            case 256:
                aes_ofb<256>(output, args["input"], key, bitset<128>(args["seed"]), std::stoi(args["size"]));
                break;
            }
        }
        else if (args["bcm"] == "cfb")
        {
            if (args["seed"].size() != 128)
            {
                throw std::invalid_argument("Invalid seed size");
            }
            if (args.count("size") == 0)
            {
                throw std::invalid_argument("No size");
            }
            switch (args["key"].size())
            {
            case 128:
                aes_cfb<128>(output, args["input"], key, bitset<128>(args["seed"]), std::stoi(args["size"]),
                             args["decrypt"] == "true");
                break;
            case 192:
                aes_cfb<192>(output, args["input"], key, bitset<128>(args["seed"]), std::stoi(args["size"]),
                             args["decrypt"] == "true");
                break;
            case 256:
                aes_cfb<256>(output, args["input"], key, bitset<128>(args["seed"]), std::stoi(args["size"]),
                             args["decrypt"] == "true");
                break;
            }
        }
        else if (args["bcm"] == "x_cbc")
        {
            if (args["seed"].size() != 128)
            {
                throw std::invalid_argument("Invalid seed size");
            }
            switch (args["key"].size())
            {
            case 384:
                aes_x_cbc<128>(output, args["input"], key, k2, k3, bitset<128>(args["seed"]), args["decrypt"] == "true",
                               std::stoi(args["size"]));
                break;
            case 448:
                aes_x_cbc<192>(output, args["input"], key, k2, k3, bitset<128>(args["seed"]), args["decrypt"] == "true",
                               std::stoi(args["size"]));
                break;
            case 512:
                aes_x_cbc<256>(output, args["input"], key, k2, k3, bitset<128>(args["seed"]), args["decrypt"] == "true",
                               std::stoi(args["size"]));
                break;
            }
        }
        else
        {
            throw std::invalid_argument("Invalid block cipher mode");
        }
    }

    // 输出结果
    if (args["encoding"] == "hex")
    {
        output = binary_to_hex_string(output);
    }
    else if (args["encoding"] == "ascii")
    {
        output = binary_to_ascii_string(output);
    }
    cout << output << endl;
}