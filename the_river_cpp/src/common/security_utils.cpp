#include "common/security_utils.h"

#include <cstdint>
#include <algorithm>
#include <iomanip>
#include <limits.h>
#include <random>
#include <sstream>
#include <vector>

#include "common/net_platform.h"

#define SHA2_ROTR(x,n) ((x>>n)|(x<<(32-n)))
#define SHA2_CH(x,y,z)  ((x&y)^(~x&z))
#define SHA2_MAJ(x,y,z) ((x&y)^(x&z)^(y&z))
#define SHA256_F1(x) (SHA2_ROTR(x,2)^SHA2_ROTR(x,13)^SHA2_ROTR(x,22))
#define SHA256_F2(x) (SHA2_ROTR(x,6)^SHA2_ROTR(x,11)^SHA2_ROTR(x,25))
#define SHA256_F3(x) (SHA2_ROTR(x,7)^SHA2_ROTR(x,18)^(x>>3))
#define SHA256_F4(x) (SHA2_ROTR(x,17)^SHA2_ROTR(x,19)^(x>>10))

static const uint32_t kSha256Table[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

std::string HashPassword(const std::string& input) {
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    std::vector<uint8_t> msg(input.begin(), input.end());
    uint64_t n = msg.size() * 8;
    msg.push_back(0x80);
    while ((msg.size() * 8) % 512 != 448) msg.push_back(0x00);
    for (int i = 7; i >= 0; --i) msg.push_back((n >> (i * 8)) & 0xFF);

    for (size_t i = 0; i < msg.size() / 64; ++i) {
        uint32_t w[64];
        for (int j = 0; j < 16; ++j) {
            w[j] = (msg[i * 64 + j * 4] << 24) |
                   (msg[i * 64 + j * 4 + 1] << 16) |
                   (msg[i * 64 + j * 4 + 2] << 8) |
                   msg[i * 64 + j * 4 + 3];
        }
        for (int j = 16; j < 64; ++j)
            w[j] = SHA256_F4(w[j - 2]) + w[j - 7] + SHA256_F3(w[j - 15]) + w[j - 16];

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], m = h[7];
        for (int j = 0; j < 64; ++j) {
            uint32_t t1 = m + SHA256_F2(e) + SHA2_CH(e, f, g) + kSha256Table[j] + w[j];
            uint32_t t2 = SHA256_F1(a) + SHA2_MAJ(a, b, c);
            m = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += m;
    }

    std::stringstream ss;
    for (int i = 0; i < 8; ++i)
        ss << std::hex << std::setw(8) << std::setfill('0') << h[i];
    return ss.str();
}

namespace {

std::vector<unsigned char> HexToBytes(const std::string& hex) {
    std::vector<unsigned char> out;
    if (hex.size() % 2 != 0) return out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        unsigned int value = 0;
        std::stringstream ss;
        ss << std::hex << hex.substr(i, 2);
        ss >> value;
        out.push_back(static_cast<unsigned char>(value & 0xff));
    }
    return out;
}

std::string BytesToHex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    for (unsigned char b : bytes)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return ss.str();
}

std::vector<unsigned char> Sha256Bytes(const std::string& input) {
    return HexToBytes(HashPassword(input));
}

std::string HmacSha256BytesHex(const std::string& key, const std::string& message) {
    std::string normalizedKey = key;
    if (normalizedKey.size() > 64) {
        const std::vector<unsigned char> keyDigest = Sha256Bytes(normalizedKey);
        normalizedKey.assign(keyDigest.begin(), keyDigest.end());
    }
    normalizedKey.resize(64, '\0');

    std::string oKeyPad(64, '\0');
    std::string iKeyPad(64, '\0');
    for (std::size_t i = 0; i < 64; ++i) {
        oKeyPad[i] = static_cast<char>(normalizedKey[i] ^ 0x5c);
        iKeyPad[i] = static_cast<char>(normalizedKey[i] ^ 0x36);
    }
    const std::vector<unsigned char> inner = Sha256Bytes(iKeyPad + message);
    const std::string innerBytes(inner.begin(), inner.end());
    return HashPassword(oKeyPad + innerBytes);
}

std::vector<unsigned char> Pbkdf2HmacSha256(const std::string& password,
                                            const std::string& saltHex,
                                            int iterations,
                                            std::size_t outputBytes) {
    const std::vector<unsigned char> salt = HexToBytes(saltHex);
    std::vector<unsigned char> output;
    output.reserve(outputBytes);
    const std::size_t hashLen = 32;
    const std::size_t blockCount = (outputBytes + hashLen - 1) / hashLen;

    for (std::size_t block = 1; block <= blockCount; ++block) {
        std::string saltBlock(salt.begin(), salt.end());
        saltBlock.push_back(static_cast<char>((block >> 24) & 0xff));
        saltBlock.push_back(static_cast<char>((block >> 16) & 0xff));
        saltBlock.push_back(static_cast<char>((block >> 8) & 0xff));
        saltBlock.push_back(static_cast<char>(block & 0xff));

        std::vector<unsigned char> u = HexToBytes(HmacSha256BytesHex(password, saltBlock));
        std::vector<unsigned char> t = u;
        for (int i = 1; i < iterations; ++i) {
            const std::string uBytes(u.begin(), u.end());
            u = HexToBytes(HmacSha256BytesHex(password, uBytes));
            for (std::size_t j = 0; j < t.size(); ++j) t[j] ^= u[j];
        }
        output.insert(output.end(), t.begin(), t.end());
    }
    output.resize(outputBytes);
    return output;
}

bool ConstantTimeEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    return diff == 0;
}

std::vector<std::string> Split(const std::string& value, char delimiter) {
    std::vector<std::string> parts;
    std::stringstream ss(value);
    std::string part;
    while (std::getline(ss, part, delimiter)) parts.push_back(part);
    return parts;
}

}  // namespace

std::string RandomHex(std::size_t bytes) {
    std::random_device rd;
    std::uniform_int_distribution<int> dis(0, 255);
    std::vector<unsigned char> out(bytes);
    for (unsigned char& b : out) b = static_cast<unsigned char>(dis(rd));
    return BytesToHex(out);
}

std::string HmacSha256Hex(const std::string& key, const std::string& message) {
    return HmacSha256BytesHex(key, message);
}

std::string MakePasswordHash(const std::string& password) {
    constexpr int kIterations = 120000;
    const std::string salt = RandomHex(16);
    const std::string digest = BytesToHex(Pbkdf2HmacSha256(password, salt, kIterations, 32));
    return "pbkdf2-sha256$" + std::to_string(kIterations) + "$" + salt + "$" + digest;
}

std::string DerivePasswordVerifier(const std::string& password, const std::string& hashSpec) {
    if (hashSpec.rfind("pbkdf2-sha256$", 0) == 0) {
        const std::vector<std::string> parts = Split(hashSpec, '$');
        if (parts.size() != 3) return "";
        int iterations = 0;
        try {
            iterations = std::stoi(parts[1]);
        } catch (...) {
            return "";
        }
        if (iterations <= 0) return "";
        const std::string digest = BytesToHex(Pbkdf2HmacSha256(password, parts[2], iterations, 32));
        return hashSpec + "$" + digest;
    }
    return "";
}

bool VerifyPasswordHash(const std::string& password, const std::string& storedHash) {
    if (storedHash.rfind("pbkdf2-sha256$", 0) == 0) {
        const std::vector<std::string> parts = Split(storedHash, '$');
        if (parts.size() != 4) return false;
        int iterations = 0;
        try {
            iterations = std::stoi(parts[1]);
        } catch (...) {
            return false;
        }
        if (iterations <= 0) return false;
        const std::string digest = BytesToHex(Pbkdf2HmacSha256(password, parts[2], iterations, 32));
        return ConstantTimeEquals(digest, parts[3]);
    }
    return false;
}

bool IsValidUsername(const std::string& username) {
    if (username.size() < 3 || username.size() > 24) return false;
    for (unsigned char c : username) {
        const bool ok = (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') ||
                        c == '_' || c == '-';
        if (!ok) return false;
    }
    return true;
}

bool IsStrongEnoughPassword(const std::string& password) {
    if (password.size() < 10 || password.size() > 128) return false;
    return password.find(':') == std::string::npos &&
           password.find('\n') == std::string::npos &&
           password.find('\r') == std::string::npos;
}

std::string MakeStableMachineId() {
    char hostname[HOST_NAME_MAX > 0 ? HOST_NAME_MAX : 256] = "node";
    gethostname(hostname, sizeof(hostname));

    unsigned long long hash = 1469598103934665603ull;
    for (unsigned char c : std::string(hostname)) {
        hash ^= c;
        hash *= 1099511628211ull;
    }

    char out[17];
    std::snprintf(out, sizeof(out), "%016llx", hash);
    return out;
}
