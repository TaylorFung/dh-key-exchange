#ifndef DH_PROTOCOL_H
#define DH_PROTOCOL_H

#include <openssl/bn.h>
#include <string>

// DH密钥交换参数
struct DHParams {
    BIGNUM* p;  // 大质数
    BIGNUM* g;  // 生成元
};

// 生成DH参数
DHParams generate_dh_params();

// 生成私钥
BIGNUM* generate_private_key(const BIGNUM* p);

// 计算公钥
BIGNUM* compute_public_key(const BIGNUM* p, const BIGNUM* g, const BIGNUM* priv_key);

// 计算共享密钥
BIGNUM* compute_shared_secret(const BIGNUM* p, const BIGNUM* their_pub_key, const BIGNUM* my_priv_key);

// 清理DH参数
void free_dh_params(DHParams& params);

#endif // DH_PROTOCOL_H
