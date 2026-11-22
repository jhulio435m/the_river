#pragma once

// X25519 identity keys and end-to-end envelopes (PROTOCOL_V2.md section 1.2).
//
// All keys and envelopes are raw bytes held in std::string. Every function
// fails closed: it returns false / an empty string on any error and never
// throws.

#include <cstddef>
#include <string>

namespace river::e2e {

constexpr std::size_t kKeyBytes = 32;    // X25519 private / public key
constexpr std::size_t kNonceBytes = 12;  // AES-GCM nonce
constexpr std::size_t kTagBytes = 16;    // AES-GCM tag
// "RE2" | version | E.pub | nonce | tag  (ciphertext length = plaintext length)
constexpr std::size_t kEnvelopeOverhead = 3 + 1 + kKeyBytes + kNonceBytes + kTagBytes;  // 64
// Largest plaintext Seal/Open accept (sanity bound, 16 MiB).
constexpr std::size_t kMaxPlaintextBytes = 16u * 1024u * 1024u;

struct KeyPair {
    std::string priv32;
    std::string pub32;
    ~KeyPair();  // wipes priv32
};

// Random keypair (priv32 / pub32 are 32 raw bytes each).
bool GenerateKeyPair(KeyPair& out);
bool PublicFromPrivate(const std::string& priv32, std::string& pub32);
// True if priv32/pub32 have the right sizes and pub32 matches priv32.
bool IsValidKeyPair(const KeyPair& keyPair);
// Wipes and clears both members.
void Clear(KeyPair& keyPair);

// First 16 bytes of SHA256(pub32), lowercase hex, groups of 4 separated by
// '-' ("xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx"). "" if pub32 is not 32 bytes.
std::string Fingerprint(const std::string& pub32);

// Spec 1.2 envelope. context is "pm" or "att:<id>"; context, fromUser and
// toUser must be non-empty and must not contain '|'.
bool Seal(const KeyPair& sender,
          const std::string& recipientPub32,
          const std::string& context,
          const std::string& fromUser,
          const std::string& toUser,
          const std::string& plaintext,
          std::string& envelope);

bool Open(const KeyPair& recipient,
          const std::string& senderPub32,
          const std::string& context,
          const std::string& fromUser,
          const std::string& toUser,
          const std::string& envelope,
          std::string& plaintext);

// "river_identity_<user>.key" (file name only; caller adds the directory).
std::string IdentityFileName(const std::string& user);

// Spec 1.2 "RIK1" identity file. Written atomically (temp file + rename),
// 0600 on POSIX. key = PBKDF2-HMAC-SHA256(password, salt, 210000, 32).
bool SaveIdentity(const std::string& path, const KeyPair& keyPair, const std::string& password);
// False if the file is missing, malformed or the password is wrong.
bool LoadIdentity(const std::string& path, const std::string& password, KeyPair& out);

}  // namespace river::e2e
