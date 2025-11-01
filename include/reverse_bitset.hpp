#pragma once
#ifndef REVERSE_BITSET_HPP
#define REVERSE_BITSET_HPP
#include <bitset>
#include <concepts>
#include <cstdint>
#include <iterator>
#include <vector>

namespace focalors
{
template <std::size_t N> class reverse_bitset : public std::bitset<N>
{
  public:
    using std::bitset<N>::bitset;
    template <class T> reverse_bitset(const T &v) noexcept
    {
        using ValueType = typename T::value_type;
        auto unit_bit_size = sizeof(ValueType) * 8;
        for (auto i : v)
        {
            *this <<= unit_bit_size;
            *this |= i;
        }
    }
    template <std::input_iterator InputIt, std::sentinel_for<InputIt> Sentinel>
    reverse_bitset(InputIt first, Sentinel last) noexcept
    {
        using ValueType = std::iter_value_t<InputIt>;
        auto unit_bit_size = sizeof(ValueType) * 8;
        for (auto it = first; it != last; ++it)
        {
            *this <<= unit_bit_size;
            *this |= *it;
        }
    }
    /*
     * @brief 重载下标运算符，实现从左到右的索引。
     * @param pos 位的位置（从0开始）。
     * @return 指向该位置的引用。
     */
    typename focalors::reverse_bitset<N>::reference operator[](std::size_t pos) noexcept
    {
        return std::bitset<N>::operator[](N - 1 - pos);
    }
    /*
     * @brief 重载下标运算符，实现从左到右的索引。
     * @param pos 位的位置（从0开始）。
     * @return 该位置的值。
     */
    constexpr bool operator[](std::size_t pos) const noexcept
    {
        return std::bitset<N>::operator[](N - 1 - pos);
    }

    using std::bitset<N>::operator=;

    template <template <typename...> class Container, typename ValueType, typename... Args>
    requires(requires(Container<ValueType, Args...> c, ValueType v) {
        {
            c.push_back(v)
            } -> std::same_as<void>;
        {
            c.insert(c.end(), v)
            } -> std::same_as<decltype(c.insert(c.end(), v))>;
    }) constexpr Container<ValueType, Args...> to_container() const
    {
        Container<ValueType, Args...> container;

        process_bits_to_values<ValueType>([&container](const ValueType &value) {
            if constexpr (requires { container.push_back(value); })
            {
                container.push_back(value);
            }
            else if constexpr (requires { container.insert(container.end(), value); })
            {
                container.insert(container.end(), value);
            }
        });

        return container;
    }

    template <typename ValueType, std::output_iterator<ValueType> OutputIt> void to_container(OutputIt dest) const
    {
        process_bits_to_values<ValueType>([&dest](const ValueType &value) { *dest++ = value; });
    }

    template <template <typename...> class Container, typename ValueType = uint8_t, typename... Args>
    requires(requires(Container<ValueType, Args...> c, ValueType v) {
        {
            c.push_back(v)
            } -> std::same_as<void>;
        {
            c.insert(c.end(), v)
            } -> std::same_as<decltype(c.insert(c.end(), v))>;
    }) constexpr
    operator Container<ValueType, Args...>() const
    {
        return to_container<Container, ValueType, Args...>();
    }

  private:
    template <typename ValueType, typename Callback> constexpr void process_bits_to_values(Callback &&store_value) const
    {
        constexpr auto value_bit_size = sizeof(ValueType) * 8;
        size_t cnt = 0;
        ValueType value = 0;

        for (size_t i = 0; i < N; i++)
        {
            value <<= 1;
            value |= (*this)[i];
            cnt++;
            if (cnt == value_bit_size)
            {
                store_value(value);
                cnt = 0;
                value = 0;
            }
        }

        // 处理不足一个完整值大小的剩余位
        if (cnt > 0)
        {
            value <<= (value_bit_size - cnt); // 将已有位移到高位，以保持原始位顺序
            store_value(value);
        }
    }
};
} // namespace focalors
#endif