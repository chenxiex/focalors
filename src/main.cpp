#include "focalors.h"
#include <cstring>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <variant>
using focalors::reverse_bitset;
using std::cout;
using std::endl;
using std::function;
using std::string;
using std::variant;
std::unordered_map<string, string> args = {
    {"decrypt", "false"}, {"bcm", "ecb"}, {"encoding", "binary"}};
void print_help()
{
    // 用中文打印Unix风格的帮助信息
    cout << "用法: crypt [选项]... [输入]\n"
            "加密或解密输入\n"
            "\n"
            "  -h, --help          显示此帮助信息并退出\n"
            "  -k, --key=KEY       使用KEY作为密钥。当使用x_cbc分组模式时，KEY=k1k2k3\n"
            "  -d, --decrypt       解密模式\n"
            "  -a, --algorithm=ALG 使用ALG算法。可选：aes, des\n"
            "  -m, --bcm=M         使用M分组模式。默认为ecb。可选：ecb, ecb_stream_cipher_padding, ecb_ciphertext_stealing_padding, cbc, ofb, cfb, x_cbc, ctr\n"
            "  -e, --encoding=ENC  使用ENC编码。可选：binary, hex, "
            "ascii。默认为binary。ascii仅影响输入和输出；hex影响输入输出、KEY、SEED\n"
            "  -f, --file=FILE     从FILE读取输入\n"
            "  -s, --seed=SEED     "
            "当使用CBC，CFG，OFB或X_CBC分组模式时，使用SEED作为初始向量；当使用CTR分组模式时，SEED为计数序列\n"
            "  -z, --size=SIZE     "
            "当使用CFB或OFB分组模式时，SIZE是每次参与异或的明文长度；当使用X_CBC分组模式时，SIZE是填充数据长度。\n"
            "  -K, --key-file=FILE 从FILE读取密钥\n"
            "  -S, --seed-file=FILE 从FILE读取SEED\n"
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
void aes_ecb(string &output, const string &input, const variant<reverse_bitset<128>, reverse_bitset<192>, reverse_bitset<256>> &key,
             const bool &decrypt)
{
    focalors::ecb(output, input, std::get<reverse_bitset<KN>>(key),
               function(decrypt ? focalors::aes_decrypt<128, KN> : focalors::aes_encrypt<128, KN>));
}
template <size_t KN>
void aes_ecb_stream_cipher_padding(string &output, const string &input,
                                   const variant<reverse_bitset<128>, reverse_bitset<192>, reverse_bitset<256>> &key, const reverse_bitset<128> &seed,
                                   const bool &decrypt)
{
    focalors::ecb_stream_cipher_padding(output, input, std::get<reverse_bitset<KN>>(key), seed, decrypt,
                                     function(decrypt ? focalors::aes_decrypt<128, KN> : focalors::aes_encrypt<128, KN>),
                                     function(focalors::aes_encrypt<128, KN>));
}
template <size_t KN>
void aes_ecb_ciphertext_stealing_padding(string &output, const string input,
                                         const variant<reverse_bitset<128>, reverse_bitset<192>, reverse_bitset<256>> &key, const reverse_bitset<128> &seed,
                                         const size_t &s, const bool &decrypt)
{
    focalors::ecb_ciphertext_stealing_padding(output, input, std::get<reverse_bitset<KN>>(key), seed, s, decrypt,
                                          function(decrypt ? focalors::aes_decrypt<128, KN> : focalors::aes_encrypt<128, KN>));
}
template <size_t KN>
void aes_cbc(string &output, const string &input, const variant<reverse_bitset<128>, reverse_bitset<192>, reverse_bitset<256>> &key,
             const reverse_bitset<128> &seed, const bool &decrypt)
{
    focalors::cbc<reverse_bitset<128>, reverse_bitset<KN>>(output, input, std::get<reverse_bitset<KN>>(key), seed, decrypt,
                                        function(decrypt ? focalors::aes_decrypt<128, KN> : focalors::aes_encrypt<128, KN>));
}
template <size_t KN>
void aes_ofb(string &output, const string &input, const variant<reverse_bitset<128>, reverse_bitset<192>, reverse_bitset<256>> &key,
             const reverse_bitset<128> &seed, const size_t &s)
{
    focalors::ofb(output, input, std::get<reverse_bitset<KN>>(key), seed, s, function(focalors::aes_encrypt<128, KN>));
}
template <size_t KN>
void aes_cfb(string &output, const string &input, const variant<reverse_bitset<128>, reverse_bitset<192>, reverse_bitset<256>> &key,
             const reverse_bitset<128> &seed, const size_t &s, const bool &decrypt)
{
    focalors::cfb(output, input, std::get<reverse_bitset<KN>>(key), seed, s, decrypt, function(focalors::aes_encrypt<128, KN>));
}
template <size_t KN>
void aes_x_cbc(string &output, const string &input, const variant<reverse_bitset<128>, reverse_bitset<192>, reverse_bitset<256>> &k1,
               const reverse_bitset<128> &k2, const reverse_bitset<128> &k3, const reverse_bitset<128> &z, const bool &decrypt,
               const size_t padding)
{
    focalors::x_cbc(output, input, std::get<reverse_bitset<KN>>(k1), k2, k3, z, decrypt, padding,
                 function(decrypt ? focalors::aes_decrypt<128, KN> : focalors::aes_encrypt<128, KN>));
}
template <size_t KN>
void aes_ctr(string &output, const string &input, const variant<reverse_bitset<128>, reverse_bitset<192>, reverse_bitset<256>> &key,
             const string &seed_string)
{
    focalors::ctr(output, input, std::get<reverse_bitset<KN>>(key), seed_string, function(focalors::aes_encrypt<128, KN>));
}
int main(int argc, char *argv[])
{
    // 解析参数
    struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},           {"key", required_argument, NULL, 'k'},
        {"decrypt", no_argument, NULL, 'd'},        {"algorithm", required_argument, NULL, 'a'},
        {"bcm", required_argument, NULL, 'm'},      {"encoding", no_argument, NULL, 'e'},
        {"file", required_argument, NULL, 'f'},     {"seed", required_argument, NULL, 's'},
        {"size", required_argument, NULL, 'z'},     {"key-file", required_argument, NULL, 'K'},
        {"seed-file", required_argument, NULL, 'S'}};
    {
        int opt;
        while ((opt = getopt_long(argc, argv, "hk:da:m:e:f:s:z:K:S:", long_options, NULL)) != -1)
        {
            switch (opt)
            {
            case 'h':
                print_help();
                return 0;
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
            case 'S':
                args["seed-file"] = optarg;
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
            print_help();
            throw std::invalid_argument("No input");
        }
        else
        {
            std::ifstream file(args["file"]);
            if (!file.is_open())
            {
                throw std::invalid_argument("Cannot open file");
            }
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

        if (args.count("seed") == 0)
        {
            if (args.count("seed-file") == 0)
            {
                throw std::invalid_argument("No seed");
            }
            else
            {
                std::ifstream file(args["seed-file"]);
                file >> args["seed"];
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
            focalors::ecb(output, args["input"], reverse_bitset<64>(args["key"]),
                       function(args["decrypt"] == "true" ? focalors::des_decrypt : focalors::des_encrypt));
        }
        else if (args["bcm"] == "ecb_stream_cipher_padding")
        {
            if (args["key"].size() != 64)
            {
                throw std::invalid_argument("Invalid key size");
            }
            if (args["seed"].size() != 64)
            {
                throw std::invalid_argument("Invalid seed size");
            }
            focalors::ecb_stream_cipher_padding(
                output, args["input"], reverse_bitset<64>(args["key"]), reverse_bitset<64>(args["seed"]), args["decrypt"] == "true",
                function(args["decrypt"] == "true" ? focalors::des_decrypt : focalors::des_encrypt),
                function(focalors::des_encrypt));
        }
        else if (args["bcm"] == "ecb_ciphertext_stealing_padding")
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
            focalors::ecb_ciphertext_stealing_padding(
                output, args["input"], reverse_bitset<64>(args["key"]), reverse_bitset<64>(args["seed"]), std::stoi(args["size"]),
                args["decrypt"] == "true",
                function(args["decrypt"] == "true" ? focalors::des_decrypt : focalors::des_encrypt));
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
            focalors::cbc<reverse_bitset<64>, reverse_bitset<64>>(
                output, args["input"], reverse_bitset<64>(args["key"]), reverse_bitset<64>(args["seed"]), args["decrypt"] == "true",
                function(args["decrypt"] == "true" ? focalors::des_decrypt : focalors::des_encrypt));
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
            focalors::ofb(output, args["input"], reverse_bitset<64>(args["key"]), reverse_bitset<64>(args["seed"]),
                       std::stoi(args["size"]), function(focalors::des_encrypt));
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
            focalors::cfb(output, args["input"], reverse_bitset<64>(args["key"]), reverse_bitset<64>(args["seed"]),
                       std::stoi(args["size"]), args["decrypt"] == "true", function(focalors::des_encrypt));
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
            reverse_bitset<64> k1(args["key"].substr(0, 64)), k2(args["key"].substr(64, 64)), k3(args["key"].substr(128, 64));
            focalors::x_cbc(output, args["input"], k1, k2, k3, reverse_bitset<64>(args["seed"]), args["decrypt"] == "true",
                         stoi(args["size"]),
                         function(args["decrypt"] == "true" ? focalors::des_decrypt : focalors::des_encrypt));
        }
        else if (args["bcm"] == "ctr")
        {
            if (args["key"].size() != 64)
            {
                throw std::invalid_argument("Invalid key size");
            }
            focalors::ctr(output, args["input"], reverse_bitset<64>(args["key"]), args["seed"], function(focalors::des_encrypt));
        }
        else
        {
            throw std::invalid_argument("Invalid group mode");
        }
    }
    else if (args["algorithm"] == "aes")
    {
        variant<reverse_bitset<128>, reverse_bitset<192>, reverse_bitset<256>> key;
        reverse_bitset<128> k2, k3;
        if (args["bcm"] == "x_cbc")
        {
            switch (args["key"].size())
            {
            case 384:
                key = reverse_bitset<128>(args["key"].substr(0, 128));
                k2 = reverse_bitset<128>(args["key"].substr(128, 128));
                k3 = reverse_bitset<128>(args["key"].substr(256, 128));
                break;
            case 448:
                key = reverse_bitset<192>(args["key"].substr(0, 192));
                k2 = reverse_bitset<128>(args["key"].substr(192, 128));
                k3 = reverse_bitset<128>(args["key"].substr(320, 128));
                break;
            case 512:
                key = reverse_bitset<256>(args["key"].substr(0, 256));
                k2 = reverse_bitset<128>(args["key"].substr(256, 128));
                k3 = reverse_bitset<128>(args["key"].substr(384, 128));
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
                key = reverse_bitset<128>(args["key"]);
                break;
            case 192:
                key = reverse_bitset<192>(args["key"]);
                break;
            case 256:
                key = reverse_bitset<256>(args["key"]);
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
        else if (args["bcm"] == "ecb_stream_cipher_padding")
        {
            switch (args["key"].size())
            {
            case 128:
                aes_ecb_stream_cipher_padding<128>(output, args["input"], key, reverse_bitset<128>(args["seed"]),
                                                   args["decrypt"] == "true");
                break;
            case 192:
                aes_ecb_stream_cipher_padding<192>(output, args["input"], key, reverse_bitset<128>(args["seed"]),
                                                   args["decrypt"] == "true");
                break;
            case 256:
                aes_ecb_stream_cipher_padding<256>(output, args["input"], key, reverse_bitset<128>(args["seed"]),
                                                   args["decrypt"] == "true");
                break;
            }
        }
        else if (args["bcm"] == "ecb_ciphertext_stealing_padding")
        {
            switch (args["key"].size())
            {
            case 128:
                aes_ecb_ciphertext_stealing_padding<128>(output, args["input"], key, reverse_bitset<128>(args["seed"]),
                                                         std::stoi(args["size"]), args["decrypt"] == "true");
                break;
            case 192:
                aes_ecb_ciphertext_stealing_padding<192>(output, args["input"], key, reverse_bitset<128>(args["seed"]),
                                                         std::stoi(args["size"]), args["decrypt"] == "true");
                break;
            case 256:
                aes_ecb_ciphertext_stealing_padding<256>(output, args["input"], key, reverse_bitset<128>(args["seed"]),
                                                         std::stoi(args["size"]), args["decrypt"] == "true");
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
                aes_cbc<128>(output, args["input"], key, reverse_bitset<128>(args["seed"]), args["decrypt"] == "true");
                break;
            case 192:
                aes_cbc<192>(output, args["input"], key, reverse_bitset<128>(args["seed"]), args["decrypt"] == "true");
                break;
            case 256:
                aes_cbc<256>(output, args["input"], key, reverse_bitset<128>(args["seed"]), args["decrypt"] == "true");
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
                aes_ofb<128>(output, args["input"], key, reverse_bitset<128>(args["seed"]), std::stoi(args["size"]));
                break;
            case 192:
                aes_ofb<192>(output, args["input"], key, reverse_bitset<128>(args["seed"]), std::stoi(args["size"]));
                break;
            case 256:
                aes_ofb<256>(output, args["input"], key, reverse_bitset<128>(args["seed"]), std::stoi(args["size"]));
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
                aes_cfb<128>(output, args["input"], key, reverse_bitset<128>(args["seed"]), std::stoi(args["size"]),
                             args["decrypt"] == "true");
                break;
            case 192:
                aes_cfb<192>(output, args["input"], key, reverse_bitset<128>(args["seed"]), std::stoi(args["size"]),
                             args["decrypt"] == "true");
                break;
            case 256:
                aes_cfb<256>(output, args["input"], key, reverse_bitset<128>(args["seed"]), std::stoi(args["size"]),
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
                aes_x_cbc<128>(output, args["input"], key, k2, k3, reverse_bitset<128>(args["seed"]), args["decrypt"] == "true",
                               std::stoi(args["size"]));
                break;
            case 448:
                aes_x_cbc<192>(output, args["input"], key, k2, k3, reverse_bitset<128>(args["seed"]), args["decrypt"] == "true",
                               std::stoi(args["size"]));
                break;
            case 512:
                aes_x_cbc<256>(output, args["input"], key, k2, k3, reverse_bitset<128>(args["seed"]), args["decrypt"] == "true",
                               std::stoi(args["size"]));
                break;
            }
        }
        else if (args["bcm"] == "ctr")
        {
            switch (args["key"].size())
            {
            case 128:
                aes_ctr<128>(output, args["input"], key, args["seed"]);
                break;
            case 192:
                aes_ctr<192>(output, args["input"], key, args["seed"]);
                break;
            case 256:
                aes_ctr<256>(output, args["input"], key, args["seed"]);
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