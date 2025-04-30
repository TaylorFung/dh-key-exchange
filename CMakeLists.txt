cmake_minimum_required(VERSION 3.10)
project(DHKeyExchange)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找OpenSSL库
find_package(OpenSSL REQUIRED)

# 包含目录
include_directories(include)

# 添加可执行文件
add_executable(dh_key_exchange
    src/base64.cpp
    src/crypto_utils.cpp
    src/dh_protocol.cpp
    src/main.cpp
)

# 链接OpenSSL库
target_link_libraries(dh_key_exchange PRIVATE OpenSSL::SSL OpenSSL::Crypto)
