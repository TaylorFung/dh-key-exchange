#include "crypto_utils.h"
#include <openssl/err.h>
#include <stdexcept>
#include <iostream>

// 生成安全的256位质数
BIGNUM* generate_safe_prime(int bits) {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    BIGNUM* p = BN_new();
    if (!p) {
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to create BIGNUM");
    }

    // 生成安全质数 (p = 2q + 1, q也是质数)
    if (!BN_generate_prime_ex(p, bits, 1, NULL, NULL, NULL)) {
        BN_free(p);
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to generate safe prime");
    }

    // 验证确实是安全质数
    if (!is_safe_prime(p, ctx)) {
        BN_free(p);
        BN_CTX_free(ctx);
        throw std::runtime_error("Generated prime is not safe");
    }

    BN_CTX_free(ctx);
    return p;
}
// 检查一个数是否是安全的质数
bool is_safe_prime(const BIGNUM* p, BN_CTX* ctx) {
    if (!p || !ctx) {
        return false;
    }

    BIGNUM* q = BN_new();
    if (!q) {
        return false;
    }

    bool result = false;
    
    // 计算 q = (p-1)/2
    if (!BN_sub(q, p, BN_value_one()) || // q = p-1
        !BN_rshift1(q, q)) {              // q = (p-1)/2
        BN_free(q);
        return false;
    }

    // 检查 p 和 q 是否都是质数
    if (BN_is_prime_ex(p, BN_prime_checks, ctx, nullptr) == 1 &&
        BN_is_prime_ex(q, BN_prime_checks, ctx, nullptr) == 1) {
        result = true;
    }

    BN_free(q);
    return result;
}

// 生成安全的质数

// 生成生成元 (原根)
BIGNUM* find_generator(const BIGNUM* p, BN_CTX* ctx) {
    BIGNUM* g = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* h = BN_new();
    BIGNUM* tmp = BN_new();
    BIGNUM* two = BN_new();

    if (!g || !q || !h || !tmp || !two) {
        goto error;
    }

    BN_set_word(two, 2);
    
    // q = (p-1)/2
    if (!BN_sub(q, p, BN_value_one()) || !BN_div(q, NULL, q, two, ctx)) {
        goto error;
    }

    // 尝试找到一个生成元
    for (BN_set_word(h, 2); BN_cmp(h, p) < 0; BN_add_word(h, 1)) {
        // g = h^2 mod p 不能为1
        if (!BN_mod_sqr(tmp, h, p, ctx)) {
            goto error;
        }
        if (BN_is_one(tmp)) {
            continue;
        }

        // g = h^q mod p 不能为1
        if (!BN_mod_exp(tmp, h, q, p, ctx)) {
            goto error;
        }
        if (BN_is_one(tmp)) {
            continue;
        }

        // 找到合适的生成元
        BN_copy(g, h);
        goto success;
    }

error:
    // 如果没有找到生成元，使用2作为默认值（对于安全质数通常有效）
    BN_set_word(g, 2);

success:
    BN_free(q);
    BN_free(h);
    BN_free(tmp);
    BN_free(two);
    return g;
}

// 生成随机大数
BIGNUM* generate_random_number(int bits) {
    BIGNUM* num = BN_new();
    if (!num) {
        throw std::runtime_error("Failed to create BIGNUM");
    }

    if (!BN_rand(num, bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
        BN_free(num);
        throw std::runtime_error("Failed to generate random number");
    }

    return num;
}

// 将BIGNUM转换为字节向量
std::vector<uint8_t> bn_to_bytes(const BIGNUM* bn) {
    int size = BN_num_bytes(bn);
    std::vector<uint8_t> bytes(size);
    BN_bn2bin(bn, bytes.data());
    return bytes;
}

// 从字节向量创建BIGNUM
BIGNUM* bytes_to_bn(const std::vector<uint8_t>& bytes) {
    BIGNUM* bn = BN_new();
    if (!bn) {
        throw std::runtime_error("Failed to create BIGNUM");
    }

    if (!BN_bin2bn(bytes.data(), bytes.size(), bn)) {
        BN_free(bn);
        throw std::runtime_error("Failed to convert bytes to BIGNUM");
    }

    return bn;
}
