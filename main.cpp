#include "crypt.h"
#include <cstring>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
using crypt::bitset;
using std::cout;
using std::endl;
using std::string;
std::unordered_map<string, string> args = {
    {"decrypt", "false"}, {"algorithm", "des"}, {"group-mode", "ecb"}, {"binary", "false"}, {"seed", string(64, '0')}};
void print_help()
{
    return;
}
string string_to_binary(const string &input)
{
    std::stringstream ss;
    for (char c : input)
    {
        ss << std::bitset<sizeof(c) * 8>(c);
    }
    return ss.str();
}
int main(int argc, char *argv[])
{
    struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"key", required_argument, NULL, 'k'},
        {"decrypt", no_argument, NULL, 'd'},
        {"algorithm", required_argument, NULL, 'a'},
        {"group-mode", required_argument, NULL, 'g'},
        {"binary", no_argument, NULL, 'b'},
        {"file", required_argument, NULL, 'f'},
        {"seed", required_argument, NULL, 's'},
        {"size", required_argument, NULL, 'z'},
        {"key-file", required_argument, NULL, 'K'},
    };
    {
        int opt;
        while ((opt = getopt_long(argc, argv, "hk:da:g:bf:s:z:K:", long_options, NULL)) != -1)
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
            case 'g':
                args["group-mode"] = optarg;
                break;
            case 'b':
                args["binary"] = "true";
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

        if (args["binary"] == "false")
        {
            args["input"] = string_to_binary(args["input"]);
            args["key"] = string_to_binary(args["key"]);
        }
    }
    if (args["algorithm"] == "des")
    {
        if (args["key"].size() != 64)
        {
            throw std::invalid_argument("Invalid key size");
        }

        string output;

        if (args["group-mode"] == "ecb")
        {
            crypt::ecb(output, args["input"], bitset<64>(args["key"]),
                       std::function(args["decrypt"] == "true" ? crypt::des_decrypt : crypt::des_encrypt));
        }
        else if (args["group-mode"] == "cbc")
        {
            if (args["seed"].size() != 64)
            {
                throw std::invalid_argument("Invalid seed size");
            }
            crypt::cbc(output, args["input"], bitset<64>(args["key"]), bitset<64>(args["seed"]),
                       args["decrypt"] == "true",
                       std::function(args["decrypt"] == "true" ? crypt::des_decrypt : crypt::des_encrypt));
        }
        else if (args["group-mode"] == "ofb")
        {
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
        else if (args["group-mode"] == "cfb")
        {
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
        else
        {
            throw std::invalid_argument("Invalid group mode");
        }
        cout << output<<endl;
    }
}