#pragma once
#ifndef TEST_H
#define TEST_H
#include "focalors.h"
#include <cstdint>
#include <vector>
struct test_case
{
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> key;
    std::vector<uint8_t> ciphertext;
};
class simple_block_cipher : public focalors::block_cipher
{
  public:
    size_t block_size() const noexcept override;
    std::vector<uint8_t> encrypt(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                                 const std::vector<uint8_t> &key) const override;
    std::vector<uint8_t> decrypt(std::vector<uint8_t>::const_iterator first, std::vector<uint8_t>::const_iterator last,
                                 const std::vector<uint8_t> &key) const override;
};
#endif