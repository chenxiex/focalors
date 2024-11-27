#pragma once
#ifndef bcm_H
#define bcm_H
#include <stdexcept>
#include <string>
#include <vector>
#include <functional>
namespace bcm
{
template <typename T> void split_input(std::vector<T> &text, const std::string &input);

void split_input_stream(std::vector<std::string> &text, const std::string &input, const int s);

template <typename T> void merge_output(std::string &output, const std::vector<T> &text);

void merge_output_stream(std::string &output, const std::vector<std::string> &text);
} // namespace bcm
#include "bcm_impl.h"
#endif