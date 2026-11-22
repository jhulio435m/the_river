#include "common/e2e_crypto.h"

#include <cstdio>
#include <fstream>
#include <string>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace river::e2e {
namespace {

const char kEnvelopeMagic[] = "RE2";
constexpr unsigned char kEnvelopeVersion = 1;
const char kInfoPrefix[] = "river-e2e-v2|";

const char kIdentityMagic[] = "RIK1";
constexpr std::size_t kIdentitySaltBytes = 16;
constexpr int kIdentityIterations = 210000;
constexpr std::size_t kIdentityFileBytes = 4 + kIdentitySaltBytes + kNonceBytes + kKeyBytes + kTagBytes;  // 80

void Wipe(std::string& value) {
    if (!value.empty()) OPENSSL_cleanse(&value[0], value.size());
    value.clear();
}

struct Secret {
    std::string v;
    Secret() = default;
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
    ~Secret() { Wipe(v); }
};

unsigned char* U(std::string& s) { return reinterpret_cast<unsigned char*>(&s[0]); }
const unsigned char* U(const std::string& s) { return reinterpret_cast<const unsigned char*>(s.data()); }

bool RandomBytes(std::size_t n, std::string& out) {
    out.assign(n, '\0');
    if (n == 0) return true;
    if (RAND_bytes(U(out), static_cast<int>(n)) != 1) {
        Wipe(out);
        return false;
    }
    return true;
}

struct PkeyHolder {
    EVP_PKEY* p = nullptr;
    ~PkeyHolder() { EVP_PKEY_free(p); }
};
struct PkeyCtxHolder {
    EVP_PKEY_CTX* p = nullptr;
    ~PkeyCtxHolder() { EVP_PKEY_CTX_free(p); }
};
struct CipherCtxHolder {
    EVP_CIPHER_CTX* p = nullptr;
    ~CipherCtxHolder() { EVP_CIPHER_CTX_free(p); }
};

bool AllZero(const std::string& s) {
    unsigned char acc = 0;
    for (char c : s) acc |= static_cast<unsigned char>(c);
    return acc == 0;
}

// X25519(priv, pub) -> 32-byte shared secret. Rejects all-zero output
// (low-order peer points).
bool X25519(const std::string& priv32, const std::string& pub32, std::string& shared) {
    shared.clear();
    if (priv32.size() != kKeyBytes || pub32.size() != kKeyBytes) return false;
    PkeyHolder priv;
    PkeyHolder pub;
    priv.p = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, U(priv32), priv32.size());
    pub.p = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, U(pub32), pub32.size());
    if (priv.p == nullptr || pub.p == nullptr) return false;
    PkeyCtxHolder ctx;
    ctx.p = EVP_PKEY_CTX_new(priv.p, nullptr);
    if (ctx.p == nullptr) return false;
    if (EVP_PKEY_derive_init(ctx.p) != 1 || EVP_PKEY_derive_set_peer(ctx.p, pub.p) != 1) return false;
    std::size_t len = 0;
    if (EVP_PKEY_derive(ctx.p, nullptr, &len) != 1 || len != kKeyBytes) return false;
    shared.assign(len, '\0');
    if (EVP_PKEY_derive(ctx.p, U(shared), &len) != 1 || len != kKeyBytes || AllZero(shared)) {
        Wipe(shared);
        return false;
    }
    return true;
}

bool HkdfSha256(const std::string& ikm, const std::string& salt, const std::string& info, std::string& out) {
    out.clear();
    PkeyCtxHolder ctx;
    ctx.p = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (ctx.p == nullptr) return false;
    if (EVP_PKEY_derive_init(ctx.p) != 1 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx.p, EVP_sha256()) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx.p, U(salt), static_cast<int>(salt.size())) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.p, U(ikm), static_cast<int>(ikm.size())) != 1 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx.p, U(info), static_cast<int>(info.size())) != 1) {
        return false;
    }
    std::size_t len = kKeyBytes;
    out.assign(kKeyBytes, '\0');
    if (EVP_PKEY_derive(ctx.p, U(out), &len) != 1 || len != kKeyBytes) {
        Wipe(out);
        return false;
    }
    return true;
}

// AES-256-GCM. Output = ciphertext | tag.
bool GcmEncrypt(const std::string& key,
                const std::string& nonce,
                const std::string& aad,
                const std::string& plaintext,
                std::string& out) {
    out.clear();
    if (key.size() != kKeyBytes || nonce.size() != kNonceBytes) return false;
    CipherCtxHolder ctx;
    ctx.p = EVP_CIPHER_CTX_new();
    if (ctx.p == nullptr) return false;
    if (EVP_EncryptInit_ex(ctx.p, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceBytes), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.p, nullptr, nullptr, U(key), U(nonce)) != 1) {
        return false;
    }
    int len = 0;
    if (!aad.empty() && EVP_EncryptUpdate(ctx.p, nullptr, &len, U(aad), static_cast<int>(aad.size())) != 1) {
        return false;
    }
    std::string buf(plaintext.size() + kTagBytes, '\0');
    int written = 0;
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx.p, U(buf), &len, U(plaintext), static_cast<int>(plaintext.size())) != 1) {
            Wipe(buf);
            return false;
        }
        written = len;
    }
    // GCM never emits bytes in Final, but pass a valid pointer regardless.
    unsigned char finalBuf[16];
    if (EVP_EncryptFinal_ex(ctx.p, finalBuf, &len) != 1 || len != 0 ||
        static_cast<std::size_t>(written) != plaintext.size()) {
        Wipe(buf);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagBytes), U(buf) + written) != 1) {
        Wipe(buf);
        return false;
    }
    out.swap(buf);
    return true;
}

bool GcmDecrypt(const std::string& key,
                const std::string& nonce,
                const std::string& aad,
                const unsigned char* data,
                std::size_t dataLen,  // ciphertext | tag
                std::string& out) {
    out.clear();
    if (key.size() != kKeyBytes || nonce.size() != kNonceBytes || dataLen < kTagBytes) return false;
    const std::size_t ctLen = dataLen - kTagBytes;
    CipherCtxHolder ctx;
    ctx.p = EVP_CIPHER_CTX_new();
    if (ctx.p == nullptr) return false;
    if (EVP_DecryptInit_ex(ctx.p, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceBytes), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.p, nullptr, nullptr, U(key), U(nonce)) != 1) {
        return false;
    }
    int len = 0;
    if (!aad.empty() && EVP_DecryptUpdate(ctx.p, nullptr, &len, U(aad), static_cast<int>(aad.size())) != 1) {
        return false;
    }
    std::string buf(ctLen, '\0');
    if (ctLen > 0) {
        if (EVP_DecryptUpdate(ctx.p, U(buf), &len, data, static_cast<int>(ctLen)) != 1 ||
            static_cast<std::size_t>(len) != ctLen) {
            Wipe(buf);
            return false;
        }
    }
    unsigned char tag[kTagBytes];
    for (std::size_t i = 0; i < kTagBytes; ++i) tag[i] = data[ctLen + i];
    if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagBytes), tag) != 1) {
        Wipe(buf);
        return false;
    }
    unsigned char finalBuf[16];
    if (EVP_DecryptFinal_ex(ctx.p, finalBuf, &len) != 1 || len != 0) {
        Wipe(buf);
        return false;
    }
    out.swap(buf);
    return true;
}

bool ValidLabel(const std::string& s) {
    return !s.empty() && s.find('|') == std::string::npos;
}

bool BuildInfo(const std::string& context, const std::string& fromUser, const std::string& toUser, std::string& info) {
    if (!ValidLabel(context) || !ValidLabel(fromUser) || !ValidLabel(toUser)) return false;
    info = std::string(kInfoPrefix) + context + "|" + fromUser + "|" + toUser;
    return true;
}

bool EnvelopeKey(const std::string& dh1,
                 const std::string& dh2,
                 const std::string& ephemeralPub,
                 const std::string& info,
                 std::string& key) {
    Secret ikm;
    ikm.v.reserve(dh1.size() + dh2.size());
    ikm.v.append(dh1);
    ikm.v.append(dh2);
    return HkdfSha256(ikm.v, ephemeralPub, info, key);
}

bool PasswordKey(const std::string& password, const std::string& salt, std::string& key) {
    key.assign(kKeyBytes, '\0');
    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()), U(salt),
                          static_cast<int>(salt.size()), kIdentityIterations, EVP_sha256(),
                          static_cast<int>(kKeyBytes), U(key)) != 1) {
        Wipe(key);
        return false;
    }
    return true;
}

bool WriteFileAtomic(const std::string& path, const std::string& data) {
    std::string suffix;
    if (!RandomBytes(6, suffix)) return false;
    static const char kDigits[] = "0123456789abcdef";
    std::string tmp = path + ".tmp.";
    for (char c : suffix) {
        tmp.push_back(kDigits[static_cast<unsigned char>(c) >> 4]);
        tmp.push_back(kDigits[static_cast<unsigned char>(c) & 0x0f]);
    }
#ifndef _WIN32
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (fd < 0) return false;
    std::size_t off = 0;
    bool ok = true;
    while (off < data.size()) {
        const ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n <= 0) {
            ok = false;
            break;
        }
        off += static_cast<std::size_t>(n);
    }
    if (ok && ::fchmod(fd, S_IRUSR | S_IWUSR) != 0) ok = false;
    if (ok && ::fsync(fd) != 0) ok = false;
    if (::close(fd) != 0) ok = false;
    if (ok && std::rename(tmp.c_str(), path.c_str()) != 0) ok = false;
    if (!ok) std::remove(tmp.c_str());
    return ok;
#else
    std::FILE* f = std::fopen(tmp.c_str(), "wb");
    if (f == nullptr) return false;
    bool ok = std::fwrite(data.data(), 1, data.size(), f) == data.size();
    if (std::fflush(f) != 0) ok = false;
    if (std::fclose(f) != 0) ok = false;
    if (ok && MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
        ok = false;
    }
    if (!ok) std::remove(tmp.c_str());
    return ok;
#endif
}

bool ReadSmallFile(const std::string& path, std::size_t maxBytes, std::string& out) {
    out.clear();
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return false;
    std::string buf(maxBytes + 1, '\0');
    in.read(&buf[0], static_cast<std::streamsize>(buf.size()));
    const std::streamsize n = in.gcount();
    if (n < 0 || in.bad()) {
        Wipe(buf);
        return false;
    }
    buf.resize(static_cast<std::size_t>(n));
    out.swap(buf);
    return true;
}

}  // namespace

KeyPair::~KeyPair() {
    Wipe(priv32);
}

void Clear(KeyPair& keyPair) {
    Wipe(keyPair.priv32);
    Wipe(keyPair.pub32);
}

bool PublicFromPrivate(const std::string& priv32, std::string& pub32) {
    pub32.clear();
    if (priv32.size() != kKeyBytes) return false;
    PkeyHolder key;
    key.p = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, U(priv32), priv32.size());
    if (key.p == nullptr) return false;
    std::string pub(kKeyBytes, '\0');
    std::size_t len = pub.size();
    if (EVP_PKEY_get_raw_public_key(key.p, U(pub), &len) != 1 || len != kKeyBytes) return false;
    pub32.swap(pub);
    return true;
}

bool GenerateKeyPair(KeyPair& out) {
    Secret priv;
    if (!RandomBytes(kKeyBytes, priv.v)) return false;
    std::string pub;
    if (!PublicFromPrivate(priv.v, pub)) return false;
    Clear(out);
    out.priv32 = priv.v;
    out.pub32 = pub;
    return true;
}

bool IsValidKeyPair(const KeyPair& keyPair) {
    if (keyPair.priv32.size() != kKeyBytes || keyPair.pub32.size() != kKeyBytes) return false;
    std::string derived;
    if (!PublicFromPrivate(keyPair.priv32, derived)) return false;
    return CRYPTO_memcmp(derived.data(), keyPair.pub32.data(), kKeyBytes) == 0;
}

std::string Fingerprint(const std::string& pub32) {
    if (pub32.size() != kKeyBytes) return "";
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(pub32.data(), pub32.size(), digest, &len, EVP_sha256(), nullptr) != 1 || len < 16) return "";
    static const char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(39);
    for (std::size_t i = 0; i < 16; ++i) {
        if (i > 0 && i % 2 == 0) out.push_back('-');
        out.push_back(kDigits[digest[i] >> 4]);
        out.push_back(kDigits[digest[i] & 0x0f]);
    }
    return out;
}

bool Seal(const KeyPair& sender,
          const std::string& recipientPub32,
          const std::string& context,
          const std::string& fromUser,
          const std::string& toUser,
          const std::string& plaintext,
          std::string& envelope) {
    envelope.clear();
    if (plaintext.size() > kMaxPlaintextBytes) return false;
    if (sender.priv32.size() != kKeyBytes || recipientPub32.size() != kKeyBytes) return false;
    std::string info;
    if (!BuildInfo(context, fromUser, toUser, info)) return false;

    KeyPair eph;
    if (!GenerateKeyPair(eph)) return false;
    Secret dh1;
    Secret dh2;
    if (!X25519(eph.priv32, recipientPub32, dh1.v)) return false;
    if (!X25519(sender.priv32, recipientPub32, dh2.v)) return false;
    Secret key;
    if (!EnvelopeKey(dh1.v, dh2.v, eph.pub32, info, key.v)) return false;

    std::string nonce;
    if (!RandomBytes(kNonceBytes, nonce)) return false;
    std::string sealed;
    if (!GcmEncrypt(key.v, nonce, info, plaintext, sealed)) return false;

    std::string out;
    out.reserve(kEnvelopeOverhead + plaintext.size());
    out.append(kEnvelopeMagic, 3);
    out.push_back(static_cast<char>(kEnvelopeVersion));
    out.append(eph.pub32);
    out.append(nonce);
    out.append(sealed);
    envelope.swap(out);
    return true;
}

bool Open(const KeyPair& recipient,
          const std::string& senderPub32,
          const std::string& context,
          const std::string& fromUser,
          const std::string& toUser,
          const std::string& envelope,
          std::string& plaintext) {
    plaintext.clear();
    if (envelope.size() < kEnvelopeOverhead || envelope.size() > kEnvelopeOverhead + kMaxPlaintextBytes) return false;
    if (envelope.compare(0, 3, kEnvelopeMagic, 3) != 0) return false;
    if (static_cast<unsigned char>(envelope[3]) != kEnvelopeVersion) return false;
    if (recipient.priv32.size() != kKeyBytes || senderPub32.size() != kKeyBytes) return false;
    std::string info;
    if (!BuildInfo(context, fromUser, toUser, info)) return false;

    const std::string ephPub = envelope.substr(4, kKeyBytes);
    const std::string nonce = envelope.substr(4 + kKeyBytes, kNonceBytes);
    const std::size_t bodyOff = 4 + kKeyBytes + kNonceBytes;

    Secret dh1;
    Secret dh2;
    if (!X25519(recipient.priv32, ephPub, dh1.v)) return false;
    if (!X25519(recipient.priv32, senderPub32, dh2.v)) return false;
    Secret key;
    if (!EnvelopeKey(dh1.v, dh2.v, ephPub, info, key.v)) return false;

    return GcmDecrypt(key.v, nonce, info, U(envelope) + bodyOff, envelope.size() - bodyOff, plaintext);
}

std::string IdentityFileName(const std::string& user) {
    if (user.empty()) return "";
    for (char c : user) {
        if (c == '/' || c == '\\' || c == ':' || c == '\0') return "";
    }
    if (user == "." || user == "..") return "";
    return "river_identity_" + user + ".key";
}

bool SaveIdentity(const std::string& path, const KeyPair& keyPair, const std::string& password) {
    if (path.empty() || password.empty() || !IsValidKeyPair(keyPair)) return false;
    std::string salt;
    std::string nonce;
    if (!RandomBytes(kIdentitySaltBytes, salt) || !RandomBytes(kNonceBytes, nonce)) return false;
    Secret key;
    if (!PasswordKey(password, salt, key.v)) return false;
    std::string sealed;
    // AAD = the "RIK1" magic (binds the format version).
    const std::string aad(kIdentityMagic, 4);
    if (!GcmEncrypt(key.v, nonce, aad, keyPair.priv32, sealed)) return false;

    std::string file;
    file.reserve(kIdentityFileBytes);
    file.append(aad);
    file.append(salt);
    file.append(nonce);
    file.append(sealed);
    if (file.size() != kIdentityFileBytes) return false;
    return WriteFileAtomic(path, file);
}

bool LoadIdentity(const std::string& path, const std::string& password, KeyPair& out) {
    if (path.empty() || password.empty()) return false;
    std::string file;
    if (!ReadSmallFile(path, kIdentityFileBytes, file)) return false;
    if (file.size() != kIdentityFileBytes || file.compare(0, 4, kIdentityMagic, 4) != 0) return false;

    const std::string salt = file.substr(4, kIdentitySaltBytes);
    const std::string nonce = file.substr(4 + kIdentitySaltBytes, kNonceBytes);
    const std::size_t bodyOff = 4 + kIdentitySaltBytes + kNonceBytes;
    Secret key;
    if (!PasswordKey(password, salt, key.v)) return false;
    Secret priv;
    const std::string aad(kIdentityMagic, 4);
    if (!GcmDecrypt(key.v, nonce, aad, U(file) + bodyOff, file.size() - bodyOff, priv.v)) return false;
    if (priv.v.size() != kKeyBytes) return false;
    std::string pub;
    if (!PublicFromPrivate(priv.v, pub)) return false;
    Clear(out);
    out.priv32 = priv.v;
    out.pub32 = pub;
    return true;
}

}  // namespace river::e2e
