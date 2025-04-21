#include <iostream>
#include <memory>
#include "dh_protocol.h"
#include "crypto_utils.h"
#include "base64.h"

// 自动释放BIGNUM的智能指针
using BNPtr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;

// 打印BIGNUM的Base64编码
void print_bn_base64(const std::string& label, const BIGNUM* bn) {
    auto bytes = bn_to_bytes(bn);
    auto encoded = base64_encode(bytes);
    std::cout << label << ": " << encoded << std::endl;
}

int main() {
    try {
        // 初始化OpenSSL
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        // 1. 生成DH参数 (p和g)
        std::cout << "Generating DH parameters..." << std::endl;
        auto params = generate_dh_params();
        
        // 使用智能指针确保资源释放
        BNPtr p(params.p, ::BN_free);
        BNPtr g(params.g, ::BN_free);
        
        // 打印参数
        print_bn_base64("Prime (p)", p.get());
        print_bn_base64("Generator (g)", g.get());

        // 2. Alice生成私钥和公钥
        std::cout << "\nAlice generating keys..." << std::endl;
        BNPtr a_priv(generate_private_key(p.get()), ::BN_free);
        BNPtr a_pub(compute_public_key(p.get(), g.get(), a_priv.get()), ::BN_free);
        
        print_bn_base64("Alice private key", a_priv.get());
        print_bn_base64("Alice public key", a_pub.get());

        // 3. Bob生成私钥和公钥
        std::cout << "\nBob generating keys..." << std::endl;
        BNPtr b_priv(generate_private_key(p.get()), ::BN_free);
        BNPtr b_pub(compute_public_key(p.get(), g.get(), b_priv.get()), ::BN_free);
        
        print_bn_base64("Bob private key", b_priv.get());
        print_bn_base64("Bob public key", b_pub.get());

        // 4. 计算共享密钥
        std::cout << "\nComputing shared secrets..." << std::endl;
        
        // Alice计算共享密钥
        BNPtr alice_shared(compute_shared_secret(p.get(), b_pub.get(), a_priv.get()), ::BN_free);
        print_bn_base64("Alice shared secret", alice_shared.get());
        
        // Bob计算共享密钥
        BNPtr bob_shared(compute_shared_secret(p.get(), a_pub.get(), b_priv.get()), ::BN_free);
        print_bn_base64("Bob shared secret", bob_shared.get());

        // 5. 验证共享密钥是否相同
        if (BN_cmp(alice_shared.get(), bob_shared.get()) == 0) {
            std::cout << "\nSuccess! Shared secrets match." << std::endl;
        } else {
            std::cerr << "\nError! Shared secrets do not match." << std::endl;
            return 1;
        }

        // 清理OpenSSL
        EVP_cleanup();
        ERR_free_strings();

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}