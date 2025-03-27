#pragma once
#ifndef UTILS_H
#define UTILS_H
#include <string>
#include <vector>
namespace focalors
{
/*
 * @brief 将二进制字符串转换为字节序列。
 * @param binary 二进制字符串。
 * @return 字节序列。
 */
std::vector<uint8_t> binary_to_bytes(const std::string &binary);
/*
 * @brief 将字节序列转换为二进制字符串。
 * @param bytes 字节序列。
 * @return 二进制字符串。
 */
std::string bytes_to_binary(const std::vector<uint8_t> &bytes);
/*
 * @brief 将二进制字符串转换为十六进制字符串。
 * @param binary 二进制字符串。
 * @return 十六进制字符串。
 */
std::string binary_to_hex(const std::string &binary);
/*
 * @brief 将十六进制字符串转换为二进制字符串。
 * @param hex 十六进制字符串。
 * @return 二进制字符串。
 */
std::string hex_to_binary(const std::string &hex);
/*
 * @brief 将十六进制字符串转换为字节序列。
 * @param hex 十六进制字符串。
 * @return 字节序列。
 */
std::vector<uint8_t> hex_to_bytes(const std::string &hex);
/*
 * @brief 将字节序列转换为十六进制字符串。
 * @param bytes 字节序列。
 * @return 十六进制字符串。
 */
std::string bytes_to_hex(const std::vector<uint8_t> &bytes);
} // namespace focalors
#endif