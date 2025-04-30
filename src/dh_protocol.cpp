#include "dh_protocol.h"
#include "crypto_utils.h"
#include <openssl/err.h>
#include <stdexcept>

// 生成DH参数
DHParams generate_dh_params() {
    DHParams params={nullptr,nullptr};
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    try {
        // 生成256位的安全质数
        params.p = generate_safe_prime(256);
        
        // 为这个质数找到生成元
        params.g = find_generator(params.p, ctx);
        
        if (!params.g) {
            throw std::runtime_error("Failed to find generator");
        }
    } catch (...) {
        if (params.p) BN_free(params.p);
        if (params.g) BN_free(params.g);
        BN_CTX_free(ctx);
        throw;
    }

    BN_CTX_free(ctx);
    return params;
}

// 生成私钥
BIGNUM* generate_private_key(const BIGNUM* p) {
    // 生成一个比p小的随机数作为私钥
    BIGNUM* priv_key = BN_new();
    if (!priv_key) {
        throw std::runtime_error("Failed to create BIGNUM");
    }

    // 生成一个比p小的随机数
    if (!BN_rand_range(priv_key, p)) {
        BN_free(priv_key);
        throw std::runtime_error("Failed to generate private key");
    }

    // 确保私钥不为0
    while (BN_is_zero(priv_key)) {
        if (!BN_rand_range(priv_key, p)) {
            BN_free(priv_key);
            throw std::runtime_error("Failed to generate private key");
        }
    }

    return priv_key;
}

// 计算公钥
BIGNUM* compute_public_key(const BIGNUM* p, const BIGNUM* g, const BIGNUM* priv_key) {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    BIGNUM* pub_key = BN_new();
    if (!pub_key) {
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to create BIGNUM");
    }

    // 计算公钥: g^priv_key mod p
    if (!BN_mod_exp(pub_key, g, priv_key, p, ctx)) {
        BN_free(pub_key);
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to compute public key");
    }

    BN_CTX_free(ctx);
    return pub_key;
}

// 计算共享密钥
BIGNUM* compute_shared_secret(const BIGNUM* p, const BIGNUM* their_pub_key, const BIGNUM* my_priv_key) {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    BIGNUM* shared_secret = BN_new();
    if (!shared_secret) {
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to create BIGNUM");
    }

    // 计算共享密钥: their_pub_key^my_priv_key mod p
    if (!BN_mod_exp(shared_secret, their_pub_key, my_priv_key, p, ctx)) {
        BN_free(shared_secret);
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to compute shared secret");
    }

    BN_CTX_free(ctx);
    return shared_secret;
}

// 清理DH参数
void free_dh_params(DHParams& params) {
    if (params.p) BN_free(params.p);
    if (params.g) BN_free(params.g);
    params.p = nullptr;
    params.g = nullptr;
}
