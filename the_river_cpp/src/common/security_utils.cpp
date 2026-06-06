#include "common/security_utils.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

constexpr int kPasswordHashIterations = 210000;
constexpr std::size_t kPasswordSaltBytes = 16;
constexpr std::size_t kPasswordDigestBytes = 32;
constexpr std::size_t kMachineIdBytes = 32;

std::string BytesToHex(const unsigned char* data, std::size_t size) {
    std::ostringstream ss;
    for (std::size_t i = 0; i < size; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::string BytesToHex(const std::vector<unsigned char>& bytes) {
    return BytesToHex(bytes.data(), bytes.size());
}

bool HexValue(char c, unsigned char& value) {
    if (c >= '0' && c <= '9') {
        value = static_cast<unsigned char>(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f') {
        value = static_cast<unsigned char>(c - 'a' + 10);
        return true;
    }
    if (c >= 'A' && c <= 'F') {
        value = static_cast<unsigned char>(c - 'A' + 10);
        return true;
    }
    return false;
}

std::vector<unsigned char> HexToBytes(const std::string& hex) {
    std::vector<unsigned char> out;
    if (hex.size() % 2 != 0) return out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        unsigned char hi = 0;
        unsigned char lo = 0;
        if (!HexValue(hex[i], hi) || !HexValue(hex[i + 1], lo)) return {};
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return out;
}

std::vector<std::string> Split(const std::string& value, char delimiter) {
    std::vector<std::string> parts;
    std::stringstream ss(value);
    std::string part;
    while (std::getline(ss, part, delimiter)) parts.push_back(part);
    return parts;
}

std::vector<unsigned char> Pbkdf2HmacSha256(const std::string& password,
                                            const std::string& saltHex,
                                            int iterations,
                                            std::size_t outputBytes) {
    const std::vector<unsigned char> salt = HexToBytes(saltHex);
    if (salt.empty() || iterations <= 0 || outputBytes == 0) return {};

    std::vector<unsigned char> output(outputBytes);
    const int ok = PKCS5_PBKDF2_HMAC(password.c_str(),
                                     static_cast<int>(password.size()),
                                     salt.data(),
                                     static_cast<int>(salt.size()),
                                     iterations,
                                     EVP_sha256(),
                                     static_cast<int>(output.size()),
                                     output.data());
    if (ok != 1) return {};
    return output;
}

bool LooksLikeMachineId(const std::string& value) {
    return value.size() == kMachineIdBytes * 2 &&
           std::all_of(value.begin(), value.end(), [](unsigned char c) {
               return (c >= '0' && c <= '9') ||
                      (c >= 'a' && c <= 'f') ||
                      (c >= 'A' && c <= 'F');
           });
}

std::string MachineIdPath() {
    const char* configured = std::getenv("THE_RIVER_MACHINE_ID_FILE");
    if (configured != nullptr && configured[0] != '\0') return configured;
    return ".the_river_machine_id";
}

std::string ReadFirstLine(const std::string& path) {
    std::ifstream input(path);
    std::string value;
    if (input.is_open()) std::getline(input, value);
    return value;
}

void RestrictFilePermissions(const std::string& path) {
#ifndef _WIN32
    chmod(path.c_str(), S_IRUSR | S_IWUSR);
#else
    (void)path;
#endif
}

bool WritePrivateLine(const std::string& path, const std::string& value) {
    std::ofstream output(path, std::ios::trunc);
    if (!output.is_open()) return false;
    output << value << "\n";
    output.close();
    RestrictFilePermissions(path);
    return true;
}

}  // namespace

std::string HashPassword(const std::string& input) {
    std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
    unsigned int digestLen = 0;
    EVP_Digest(input.data(),
               input.size(),
               digest.data(),
               &digestLen,
               EVP_sha256(),
               nullptr);
    return BytesToHex(digest.data(), digestLen);
}

std::string RandomHex(std::size_t bytes) {
    std::vector<unsigned char> out(bytes);
    if (out.empty()) return "";
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) return "";
    return BytesToHex(out);
}

std::string HmacSha256Hex(const std::string& key, const std::string& message) {
    std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
    unsigned int digestLen = 0;
    HMAC(EVP_sha256(),
         key.data(),
         static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(message.data()),
         message.size(),
         digest.data(),
         &digestLen);
    return BytesToHex(digest.data(), digestLen);
}

std::string MakePasswordHash(const std::string& password) {
    const std::string salt = RandomHex(kPasswordSaltBytes);
    const std::vector<unsigned char> digest =
        Pbkdf2HmacSha256(password, salt, kPasswordHashIterations, kPasswordDigestBytes);
    if (salt.empty() || digest.empty()) return "";
    return "pbkdf2-sha256$" + std::to_string(kPasswordHashIterations) + "$" + salt + "$" + BytesToHex(digest);
}

std::string DerivePasswordVerifier(const std::string& password, const std::string& hashSpec) {
    if (hashSpec.rfind("pbkdf2-sha256$", 0) != 0) return "";

    const std::vector<std::string> parts = Split(hashSpec, '$');
    if (parts.size() != 3) return "";

    int iterations = 0;
    try {
        iterations = std::stoi(parts[1]);
    } catch (...) {
        return "";
    }
    if (iterations <= 0) return "";

    const std::vector<unsigned char> digest =
        Pbkdf2HmacSha256(password, parts[2], iterations, kPasswordDigestBytes);
    if (digest.empty()) return "";
    return hashSpec + "$" + BytesToHex(digest);
}

bool ConstantTimeEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

bool VerifyPasswordHash(const std::string& password, const std::string& storedHash) {
    if (storedHash.rfind("pbkdf2-sha256$", 0) != 0) return false;

    const std::vector<std::string> parts = Split(storedHash, '$');
    if (parts.size() != 4) return false;

    const std::string verifier = DerivePasswordVerifier(password, parts[0] + "$" + parts[1] + "$" + parts[2]);
    if (verifier.empty()) return false;

    const std::vector<std::string> verifierParts = Split(verifier, '$');
    return verifierParts.size() == 4 && ConstantTimeEquals(verifierParts[3], parts[3]);
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
    if (password.size() < 12 || password.size() > 128) return false;
    return password.find(':') == std::string::npos &&
           password.find('\n') == std::string::npos &&
           password.find('\r') == std::string::npos;
}

std::string MakeStableMachineId() {
    const char* explicitId = std::getenv("THE_RIVER_MACHINE_ID");
    if (explicitId != nullptr && LooksLikeMachineId(explicitId)) return explicitId;

    const std::string path = MachineIdPath();
    const std::string existing = ReadFirstLine(path);
    if (LooksLikeMachineId(existing)) return existing;

    const std::string generated = RandomHex(kMachineIdBytes);
    if (generated.empty()) return "";
    WritePrivateLine(path, generated);
    return generated;
}
