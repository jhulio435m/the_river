#include "common/scram.h"

#include <cstring>
#include <utility>
#include <string>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "common/security_utils.h"

namespace river::scram {
namespace {

const char kPrefix[] = "scram-sha256$";
const char kV1Prefix[] = "pbkdf2-sha256$";
const char kAuthPrefix[] = "river-auth-v2|";

// security_utils.cpp uses kPasswordHashIterations = 210000 for v1 hashes;
// new SCRAM credentials never use fewer.
constexpr int kV1PasswordHashIterations = 210000;
constexpr int kNewIterations =
    kDefaultIterations > kV1PasswordHashIterations ? kDefaultIterations : kV1PasswordHashIterations;

constexpr std::size_t kMinSaltBytes = 16;
constexpr std::size_t kMaxSaltBytes = 64;

void Wipe(std::string& value) {
    if (!value.empty()) OPENSSL_cleanse(&value[0], value.size());
    value.clear();
}

// RAII wiper for local secrets.
struct Secret {
    std::string v;
    Secret() = default;
    explicit Secret(std::string s) : v(std::move(s)) {}
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
    ~Secret() { Wipe(v); }
};

int HexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool HexDecode(const std::string& hex, std::string& out) {
    out.clear();
    if (hex.empty() || hex.size() % 2 != 0) return false;
    out.resize(hex.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        const int hi = HexNibble(hex[2 * i]);
        const int lo = HexNibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            Wipe(out);
            return false;
        }
        out[i] = static_cast<char>((hi << 4) | lo);
    }
    return true;
}

std::string HexEncode(const std::string& raw) {
    static const char kDigits[] = "0123456789abcdef";
    std::string out;
    out.resize(raw.size() * 2);
    for (std::size_t i = 0; i < raw.size(); ++i) {
        const unsigned char b = static_cast<unsigned char>(raw[i]);
        out[2 * i] = kDigits[b >> 4];
        out[2 * i + 1] = kDigits[b & 0x0f];
    }
    return out;
}

std::string ToLowerHex(const std::string& hex) {
    std::string out = hex;
    for (char& c : out) {
        if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}

bool HmacSha256(const std::string& key, const std::string& msg, std::string& out) {
    out.assign(kKeyBytes, '\0');
    unsigned int len = 0;
    const unsigned char* r = HMAC(EVP_sha256(),
                                  key.data(),
                                  static_cast<int>(key.size()),
                                  reinterpret_cast<const unsigned char*>(msg.data()),
                                  msg.size(),
                                  reinterpret_cast<unsigned char*>(&out[0]),
                                  &len);
    if (r == nullptr || len != kKeyBytes) {
        Wipe(out);
        return false;
    }
    return true;
}

bool Sha256(const std::string& in, std::string& out) {
    out.assign(kKeyBytes, '\0');
    unsigned int len = 0;
    if (EVP_Digest(in.data(), in.size(), reinterpret_cast<unsigned char*>(&out[0]), &len, EVP_sha256(), nullptr) != 1 ||
        len != kKeyBytes) {
        Wipe(out);
        return false;
    }
    return true;
}

bool Pbkdf2(const std::string& password, const std::string& saltRaw, int iterations, std::string& out) {
    out.assign(kKeyBytes, '\0');
    if (PKCS5_PBKDF2_HMAC(password.data(),
                          static_cast<int>(password.size()),
                          reinterpret_cast<const unsigned char*>(saltRaw.data()),
                          static_cast<int>(saltRaw.size()),
                          iterations,
                          EVP_sha256(),
                          static_cast<int>(kKeyBytes),
                          reinterpret_cast<unsigned char*>(&out[0])) != 1) {
        Wipe(out);
        return false;
    }
    return true;
}

// From SaltedPassword (raw), compute ClientKey, StoredKey and ServerKey.
bool DeriveKeys(const std::string& saltedPassword, std::string& clientKey, std::string& storedKey, std::string& serverKey) {
    if (saltedPassword.size() != kKeyBytes) return false;
    if (!HmacSha256(saltedPassword, "Client Key", clientKey)) return false;
    if (!Sha256(clientKey, storedKey)) {
        Wipe(clientKey);
        return false;
    }
    if (!HmacSha256(saltedPassword, "Server Key", serverKey)) {
        Wipe(clientKey);
        Wipe(storedKey);
        return false;
    }
    return true;
}

bool FromSaltedRaw(int iterations, const std::string& saltHex, const std::string& saltedPassword, Credential& out) {
    Secret clientKey;
    std::string storedKey;
    std::string serverKey;
    if (!DeriveKeys(saltedPassword, clientKey.v, storedKey, serverKey)) return false;
    Credential c;
    c.iterations = iterations;
    c.saltHex = ToLowerHex(saltHex);
    c.storedKeyHex = HexEncode(storedKey);
    c.serverKeyHex = HexEncode(serverKey);
    Wipe(serverKey);
    out = c;
    return true;
}

bool ParseInt(const std::string& s, int& out) {
    if (s.empty() || s.size() > 9) return false;  // <= 999,999,999
    long long v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
    }
    if (s.size() > 1 && s[0] == '0') return false;  // canonical form only
    out = static_cast<int>(v);
    return true;
}

std::size_t SplitDollar(const std::string& s, std::string* parts, std::size_t maxParts) {
    std::size_t count = 0;
    std::size_t start = 0;
    while (true) {
        const std::size_t pos = s.find('$', start);
        if (count == maxParts) return maxParts + 1;  // too many
        parts[count++] = s.substr(start, pos == std::string::npos ? std::string::npos : pos - start);
        if (pos == std::string::npos) break;
        start = pos + 1;
    }
    return count;
}

bool DecodeCredentialKey(const std::string& hex, std::string& raw) {
    return IsHexString(hex, kKeyBytes * 2) && HexDecode(hex, raw);
}

}  // namespace

bool IsValidIterations(int iterations) {
    return iterations >= kMinIterations && iterations <= kMaxIterations;
}

bool IsHexString(const std::string& value, std::size_t exactHexChars) {
    if (value.empty() || value.size() % 2 != 0) return false;
    if (exactHexChars != 0 && value.size() != exactHexChars) return false;
    for (char c : value) {
        if (HexNibble(c) < 0) return false;
    }
    return true;
}

bool IsValidSaltHex(const std::string& saltHex) {
    return IsHexString(saltHex, 0) && saltHex.size() >= kMinSaltBytes * 2 && saltHex.size() <= kMaxSaltBytes * 2;
}

std::string RandomNonceHex(std::size_t bytes) {
    if (bytes == 0 || bytes > 1024) return "";
    std::string raw(bytes, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&raw[0]), static_cast<int>(bytes)) != 1) return "";
    return HexEncode(raw);
}

bool MakeCredential(const std::string& password, Credential& out) {
    if (password.empty()) return false;
    const std::string saltHex = RandomNonceHex(kSaltBytes);
    std::string salt;
    if (saltHex.empty() || !HexDecode(saltHex, salt)) return false;
    Secret salted;
    if (!Pbkdf2(password, salt, kNewIterations, salted.v)) return false;
    return FromSaltedRaw(kNewIterations, saltHex, salted.v, out);
}

bool CredentialFromSaltedPassword(int iterations,
                                  const std::string& saltHex,
                                  const std::string& saltedPasswordHex,
                                  Credential& out) {
    if (!IsValidIterations(iterations) || !IsValidSaltHex(saltHex)) return false;
    if (!IsHexString(saltedPasswordHex, kKeyBytes * 2)) return false;
    Secret salted;
    if (!HexDecode(saltedPasswordHex, salted.v)) return false;
    return FromSaltedRaw(iterations, saltHex, salted.v, out);
}

bool CredentialFromV1Hash(const std::string& v1Hash, Credential& out) {
    if (v1Hash.compare(0, sizeof(kV1Prefix) - 1, kV1Prefix) != 0) return false;
    std::string parts[4];
    if (SplitDollar(v1Hash, parts, 4) != 4) return false;
    int iterations = 0;
    if (!ParseInt(parts[1], iterations)) return false;
    return CredentialFromSaltedPassword(iterations, parts[2], parts[3], out);
}

bool CredentialFromParts(int iterations,
                         const std::string& saltHex,
                         const std::string& storedKeyHex,
                         const std::string& serverKeyHex,
                         Credential& out) {
    if (!IsValidIterations(iterations) || !IsValidSaltHex(saltHex)) return false;
    if (!IsHexString(storedKeyHex, kKeyBytes * 2) || !IsHexString(serverKeyHex, kKeyBytes * 2)) return false;
    Credential c;
    c.iterations = iterations;
    c.saltHex = ToLowerHex(saltHex);
    c.storedKeyHex = ToLowerHex(storedKeyHex);
    c.serverKeyHex = ToLowerHex(serverKeyHex);
    out = c;
    return true;
}

std::string Serialize(const Credential& credential) {
    Credential c;
    if (!CredentialFromParts(credential.iterations, credential.saltHex, credential.storedKeyHex,
                             credential.serverKeyHex, c)) {
        return "";
    }
    return std::string(kPrefix) + std::to_string(c.iterations) + "$" + c.saltHex + "$" + c.storedKeyHex + "$" +
           c.serverKeyHex;
}

bool IsScramCredentialString(const std::string& value) {
    return value.compare(0, sizeof(kPrefix) - 1, kPrefix) == 0;
}

bool Parse(const std::string& serialized, Credential& out) {
    if (!IsScramCredentialString(serialized)) return false;
    std::string parts[5];
    if (SplitDollar(serialized, parts, 5) != 5) return false;
    int iterations = 0;
    if (!ParseInt(parts[1], iterations)) return false;
    return CredentialFromParts(iterations, parts[2], parts[3], parts[4], out);
}

std::string BuildAuthMessage(const std::string& user,
                             const std::string& hwid,
                             const std::string& clientNonceHex,
                             const std::string& combinedNonceHex,
                             const std::string& saltHex,
                             int iterations) {
    const std::string* fields[] = {&user, &hwid, &clientNonceHex, &combinedNonceHex, &saltHex};
    for (const std::string* f : fields) {
        if (f->empty() || f->find('|') != std::string::npos) return "";
    }
    if (!IsValidIterations(iterations)) return "";
    return std::string(kAuthPrefix) + user + "|" + hwid + "|" + clientNonceHex + "|" + combinedNonceHex + "|" +
           saltHex + "|" + std::to_string(iterations);
}

bool ComputeClientProof(const std::string& password,
                        const std::string& saltHex,
                        int iterations,
                        const std::string& authMessage,
                        std::string& clientProofRaw,
                        std::string& expectedServerSignatureRaw) {
    clientProofRaw.clear();
    expectedServerSignatureRaw.clear();
    if (password.empty() || authMessage.empty()) return false;
    if (!IsValidIterations(iterations) || !IsValidSaltHex(saltHex)) return false;

    std::string salt;
    if (!HexDecode(saltHex, salt)) return false;
    Secret salted;
    if (!Pbkdf2(password, salt, iterations, salted.v)) return false;

    Secret clientKey;
    Secret storedKey;
    Secret serverKey;
    if (!DeriveKeys(salted.v, clientKey.v, storedKey.v, serverKey.v)) return false;

    Secret clientSig;
    if (!HmacSha256(storedKey.v, authMessage, clientSig.v)) return false;
    std::string proof(kKeyBytes, '\0');
    for (std::size_t i = 0; i < kKeyBytes; ++i) {
        proof[i] = static_cast<char>(clientKey.v[i] ^ clientSig.v[i]);
    }
    std::string serverSig;
    if (!HmacSha256(serverKey.v, authMessage, serverSig)) {
        Wipe(proof);
        return false;
    }
    clientProofRaw = proof;
    expectedServerSignatureRaw = serverSig;
    Wipe(proof);
    return true;
}

bool VerifyServerSignature(const std::string& expectedServerSignatureRaw,
                           const std::string& receivedServerSignatureRaw) {
    if (expectedServerSignatureRaw.size() != kKeyBytes) return false;
    return ConstantTimeEquals(expectedServerSignatureRaw, receivedServerSignatureRaw);
}

bool VerifyClientProof(const Credential& credential,
                       const std::string& authMessage,
                       const std::string& clientProofRaw) {
    if (authMessage.empty() || clientProofRaw.size() != kKeyBytes) return false;
    if (!IsValidIterations(credential.iterations) || !IsValidSaltHex(credential.saltHex)) return false;
    std::string storedKey;
    if (!DecodeCredentialKey(credential.storedKeyHex, storedKey)) return false;

    Secret clientSig;
    if (!HmacSha256(storedKey, authMessage, clientSig.v)) return false;
    Secret clientKey;
    clientKey.v.assign(kKeyBytes, '\0');
    for (std::size_t i = 0; i < kKeyBytes; ++i) {
        clientKey.v[i] = static_cast<char>(clientProofRaw[i] ^ clientSig.v[i]);
    }
    std::string candidate;
    if (!Sha256(clientKey.v, candidate)) return false;
    return ConstantTimeEquals(candidate, storedKey);
}

std::string ServerSignature(const Credential& credential, const std::string& authMessage) {
    if (authMessage.empty()) return "";
    Secret serverKey;
    if (!DecodeCredentialKey(credential.serverKeyHex, serverKey.v)) return "";
    std::string sig;
    if (!HmacSha256(serverKey.v, authMessage, sig)) return "";
    return sig;
}

}  // namespace river::scram
