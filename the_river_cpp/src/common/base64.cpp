#include "common/base64.h"

#include <array>

namespace river::base64 {

namespace {

constexpr char kAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

int DecodeValue(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return -2;
    return -1;
}

}  // namespace

std::string Encode(const unsigned char* data, std::size_t size) {
    std::string output;
    output.reserve(((size + 2) / 3) * 4);

    for (std::size_t i = 0; i < size; i += 3) {
        const unsigned int octetA = data[i];
        const unsigned int octetB = i + 1 < size ? data[i + 1] : 0;
        const unsigned int octetC = i + 2 < size ? data[i + 2] : 0;
        const unsigned int triple = (octetA << 16) | (octetB << 8) | octetC;

        output.push_back(kAlphabet[(triple >> 18) & 0x3F]);
        output.push_back(kAlphabet[(triple >> 12) & 0x3F]);
        output.push_back(i + 1 < size ? kAlphabet[(triple >> 6) & 0x3F] : '=');
        output.push_back(i + 2 < size ? kAlphabet[triple & 0x3F] : '=');
    }

    return output;
}

std::string Encode(const std::vector<unsigned char>& data) {
    if (data.empty()) return "";
    return Encode(data.data(), data.size());
}

std::string EncodeString(const std::string& value) {
    return Encode(reinterpret_cast<const unsigned char*>(value.data()), value.size());
}

bool Decode(const std::string& input, std::vector<unsigned char>& output) {
    if (input.empty()) {
        output.clear();
        return true;
    }
    if (input.size() % 4 != 0) return false;

    output.clear();
    output.reserve((input.size() / 4) * 3);

    for (std::size_t i = 0; i < input.size(); i += 4) {
        const int v0 = DecodeValue(static_cast<unsigned char>(input[i]));
        const int v1 = DecodeValue(static_cast<unsigned char>(input[i + 1]));
        const int v2 = DecodeValue(static_cast<unsigned char>(input[i + 2]));
        const int v3 = DecodeValue(static_cast<unsigned char>(input[i + 3]));
        if (v0 < 0 || v1 < 0 || v2 == -1 || v3 == -1) return false;

        const unsigned int triple =
            (static_cast<unsigned int>(v0) << 18) |
            (static_cast<unsigned int>(v1) << 12) |
            (static_cast<unsigned int>(v2 < 0 ? 0 : v2) << 6) |
            static_cast<unsigned int>(v3 < 0 ? 0 : v3);

        output.push_back(static_cast<unsigned char>((triple >> 16) & 0xFF));
        if (v2 != -2) output.push_back(static_cast<unsigned char>((triple >> 8) & 0xFF));
        if (v3 != -2) output.push_back(static_cast<unsigned char>(triple & 0xFF));
    }

    return true;
}

bool DecodeToString(const std::string& input, std::string& output) {
    std::vector<unsigned char> decoded;
    if (!Decode(input, decoded)) return false;
    output.assign(decoded.begin(), decoded.end());
    return true;
}

}  // namespace river::base64
