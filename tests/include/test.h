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
    std::vector<uint8_t> iv;
};
#endif