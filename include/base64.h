#ifndef BASE64_H
#define BASE64_H

#include <string>
#include <vector>
#include <cstdint>
// Base64编码函数：将二进制数据转换为Base64字符串
std::string base64_encode(const std::vector<uint8_t>& data);

// Base64解码函数：将Base64字符串转换为二进制数据
std::vector<uint8_t> base64_decode(const std::string& encoded_string);

#endif // BASE64_H
