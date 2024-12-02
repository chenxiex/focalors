### 编译
```bash
$ make
```
在 Arch Linux 上测试通过。

### 使用
```bash
$ ./crypt --help
用法: crypt [选项]... [输入]
加密或解密输入

  -h, --help          显示此帮助信息并退出
  -k, --key=KEY       使用KEY作为密钥。当使用x_cbc分组模式时，KEY=k1k2k3
  -d, --decrypt       解密模式
  -a, --algorithm=ALG 使用ALG算法。默认为des。可选：aes, des
  -m, --bcm=M         使用M分组模式。默认为ecb。可选：ecb, ecb_stream_cipher_padding, ecb_ciphertext_stealing_padding, cbc, ofb, cfb, x_cbc, ctr
  -e, --encoding=ENC  使用ENC编码。可选：binary, hex, ascii。默认为binary。ascii仅影响输入和输出；hex影响输入输出、KEY、SEED
  -f, --file=FILE     从FILE读取输入
  -s, --seed=SEED     当使用CBC，CFG，OFB或X_CBC分组模式时，使用SEED作为初始向量；当使用CTR分组模式时，SEED为计数序列
  -z, --size=SIZE     当使用CFB或OFB分组模式时，SIZE是每次参与异或的明文长度；当使用X_CBC分组模式时，SIZE是填充数据长度。
  -K, --key-file=FILE 从FILE读取密钥
  -S, --seed-file=FILE 从FILE读取SEED
```