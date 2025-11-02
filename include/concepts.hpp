#pragma once
#ifndef CONCEPTS_HPP
#define CONCEPTS_HPP
#include <concepts>
#include <cstdint>
#include <vector>
namespace focalors
{
// Cipher
template <typename T>
concept Cipher = requires(T c, std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                          std::vector<uint8_t>::iterator dest)
{
    {
        c.encrypt(first, last, dest)
        } -> std::same_as<std::vector<uint8_t>>;
    {
        c.decrypt(first, last, dest)
        } -> std::same_as<std::vector<uint8_t>>;
};
// Block cipher
template <typename T>
concept BlockCipher = requires(T c, std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::iterator dest)
{
    {
        c.block_size()
        } -> std::convertible_to<std::size_t>;
    {
        c.encrypt(first, dest)
        } -> std::same_as<void>;
    {
        c.decrypt(first, dest)
        } -> std::same_as<void>;
};
// Byte input iterator
template <typename It>
concept ByteInputIt = std::input_iterator<It> && requires(It it)
{
    {
        *it
        } -> std::convertible_to<uint8_t>;
};
} // namespace focalors
#endif