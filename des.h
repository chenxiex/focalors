#ifndef DES_H
#define DES_H
#include <bitset>

namespace des
{
template <std::size_t N> class bitset : public std::bitset<N>
{
  public:
    using std::bitset<N>::bitset; // 继承 std::bitset 的构造函数
    using std::bitset<N>::operator=; // 继承 std::bitset 的赋值运算符

    // 重载[]运算符，支持从左向右索引，返回可修改的引用
    typename std::bitset<N>::reference operator[](std::size_t pos)
    {
        return std::bitset<N>::operator[](N - 1 - pos); // 左向右索引
    }

    // 重载[]运算符，支持从左向右索引，返回只读的值
    bool operator[](std::size_t pos) const
    {
        return std::bitset<N>::operator[](N - 1 - pos); // 左向右索引
    }
};
void des_encrypt(des::bitset<64> &ciphertext, const des::bitset<64> &plaintext, const des::bitset<64> &key);
void des_decrypt(des::bitset<64> &plaintext, const des::bitset<64> &ciphertext, const des::bitset<64> &key);
} // namespace des

#endif // DES_H