#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <vector>
#include <string>
#include <openssl/bn.h>
#include <openssl/dh.h>

// 生成安全的256位质数
BIGNUM* generate_safe_prime(int bits);

// 检查一个数是否是安全的质数
bool is_safe_prime(const BIGNUM* p, BN_CTX* ctx);

// 生成生成元 (原根)
BIGNUM* find_generator(const BIGNUM* p, BN_CTX* ctx);

// 生成随机大数
BIGNUM* generate_random_number(int bits);

// 将BIGNUM转换为字节向量
std::vector<uint8_t> bn_to_bytes(const BIGNUM* bn);

// 从字节向量创建BIGNUM
BIGNUM* bytes_to_bn(const std::vector<uint8_t>& bytes);

#endif // CRYPTO_UTILS_H
