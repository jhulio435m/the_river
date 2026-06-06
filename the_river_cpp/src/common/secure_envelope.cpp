#include "common/secure_envelope.h"

#include <sstream>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "common/base64.h"
#include "common/security_utils.h"
#include "common/shared_config.h"

namespace river {
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

std::vector<std::string> Split(const std::string& value, char delimiter) {
    std::vector<std::string> parts;
    std::stringstream ss(value);
    std::string part;
    while (std::getline(ss, part, delimiter)) parts.push_back(part);
    return parts;
}

std::vector<unsigned char> EnvelopeKey() {
    if (!IsEncryptionKeyStrong(EncryptionKey())) return {};
    return HexToBytes(HashPassword("the-river-envelope-v3|" + EncryptionKey()));
}

}  // namespace

std::string SealPayload(const std::string& plainText) {
    std::vector<unsigned char> key = EnvelopeKey();
    std::vector<unsigned char> nonce(12);
    if (key.size() != 32 || RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) return "";

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return "";

    std::vector<unsigned char> cipher(plainText.size() + 16);
    int outLen = 0;
    int totalLen = 0;
    std::vector<unsigned char> tag(16);
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1 &&
              EVP_EncryptUpdate(ctx,
                                cipher.data(),
                                &outLen,
                                reinterpret_cast<const unsigned char*>(plainText.data()),
                                static_cast<int>(plainText.size())) == 1;
    totalLen = outLen;
    ok = ok && EVP_EncryptFinal_ex(ctx, cipher.data() + totalLen, &outLen) == 1;
    totalLen += outLen;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return "";

    cipher.resize(static_cast<std::size_t>(totalLen));
    return "v3|" + base64::Encode(nonce) + "|" + base64::Encode(cipher) + "|" + base64::Encode(tag);
}

std::string SealPayloadBinary(const std::string& plainText) {
    std::vector<unsigned char> key = EnvelopeKey();
    std::vector<unsigned char> nonce(12);
    if (key.size() != 32 || RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) return "";

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return "";

    std::vector<unsigned char> cipher(plainText.size() + 16);
    int outLen = 0;
    int totalLen = 0;
    std::vector<unsigned char> tag(16);
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1 &&
              EVP_EncryptUpdate(ctx,
                                cipher.data(),
                                &outLen,
                                reinterpret_cast<const unsigned char*>(plainText.data()),
                                static_cast<int>(plainText.size())) == 1;
    totalLen = outLen;
    ok = ok && EVP_EncryptFinal_ex(ctx, cipher.data() + totalLen, &outLen) == 1;
    totalLen += outLen;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return "";

    std::string out = "RV4";
    out.append(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    out.append(reinterpret_cast<const char*>(tag.data()), tag.size());
    out.append(reinterpret_cast<const char*>(cipher.data()), static_cast<std::size_t>(totalLen));
    return out;
}

bool OpenPayload(const std::string& sealedPayload, std::string& plainText) {
    if (sealedPayload.rfind("v3|", 0) != 0) return false;

    const std::vector<std::string> parts = Split(sealedPayload, '|');
    if (parts.size() != 4) return false;

    std::vector<unsigned char> nonce;
    std::vector<unsigned char> cipher;
    std::vector<unsigned char> tag;
    std::vector<unsigned char> key = EnvelopeKey();
    if (key.size() != 32 ||
        !base64::Decode(parts[1], nonce) ||
        !base64::Decode(parts[2], cipher) ||
        !base64::Decode(parts[3], tag) ||
        nonce.size() != 12 ||
        tag.size() != 16) {
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return false;

    std::vector<unsigned char> plain(cipher.size() + 16);
    int outLen = 0;
    int totalLen = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1 &&
              EVP_DecryptUpdate(ctx,
                                plain.data(),
                                &outLen,
                                cipher.data(),
                                static_cast<int>(cipher.size())) == 1;
    totalLen = outLen;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data()) == 1 &&
         EVP_DecryptFinal_ex(ctx, plain.data() + totalLen, &outLen) == 1;
    totalLen += outLen;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return false;

    plainText.assign(reinterpret_cast<const char*>(plain.data()), static_cast<std::size_t>(totalLen));
    return true;
}

bool OpenPayloadBinary(const std::string& sealedPayload, std::string& plainText) {
    if (sealedPayload.size() < 3 + 12 + 16 || sealedPayload.compare(0, 3, "RV4") != 0) return false;

    const unsigned char* nonce = reinterpret_cast<const unsigned char*>(sealedPayload.data() + 3);
    const unsigned char* tag = reinterpret_cast<const unsigned char*>(sealedPayload.data() + 15);
    const unsigned char* cipher = reinterpret_cast<const unsigned char*>(sealedPayload.data() + 31);
    const std::size_t cipherSize = sealedPayload.size() - 31;
    std::vector<unsigned char> key = EnvelopeKey();
    if (key.size() != 32) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return false;

    std::vector<unsigned char> plain(cipherSize + 16);
    int outLen = 0;
    int totalLen = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) == 1 &&
              EVP_DecryptUpdate(ctx, plain.data(), &outLen, cipher, static_cast<int>(cipherSize)) == 1;
    totalLen = outLen;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char*>(tag)) == 1 &&
         EVP_DecryptFinal_ex(ctx, plain.data() + totalLen, &outLen) == 1;
    totalLen += outLen;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return false;

    plainText.assign(reinterpret_cast<const char*>(plain.data()), static_cast<std::size_t>(totalLen));
    return true;
}

}
