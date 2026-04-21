#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace river::base64 {

std::string Encode(const unsigned char* data, std::size_t size);
std::string Encode(const std::vector<unsigned char>& data);
std::string EncodeString(const std::string& value);

bool Decode(const std::string& input, std::vector<unsigned char>& output);
bool DecodeToString(const std::string& input, std::string& output);

}  // namespace river::base64
