#pragma once

// SCRAM-SHA-256 style credentials (PROTOCOL_V2.md section 1.1).
//
// All binary values (proofs, signatures) are raw bytes held in std::string.
// Every function fails closed: it returns false / an empty string on any
// error and never throws.

#include <cstddef>
#include <string>

namespace river::scram {

// Iterations used for newly created credentials (spec minimum 210000).
constexpr int kDefaultIterations = 210000;
// Lowest iteration count accepted from the network or the database
// (spec 2.1: server validates iter >= 100000). Clients also refuse to
// compute a proof for a lower count, so a fake server cannot downgrade it.
constexpr int kMinIterations = 100000;
// Upper bound to stop a peer from forcing absurd PBKDF2 work.
constexpr int kMaxIterations = 10000000;
// Salt length for new credentials (bytes). Parsed salts may be 16..64 bytes.
constexpr std::size_t kSaltBytes = 16;
constexpr std::size_t kKeyBytes = 32;  // SHA-256 output size

struct Credential {
    int iterations = 0;
    std::string saltHex;       // lowercase hex of the raw salt
    std::string storedKeyHex;  // lowercase hex, 64 chars
    std::string serverKeyHex;  // lowercase hex, 64 chars
};

// New credential with a random 16-byte salt and kDefaultIterations
// (or the v1 kPasswordHashIterations constant, whichever is higher).
bool MakeCredential(const std::string& password, Credential& out);

// Build a credential from an already computed SaltedPassword (hex).
// Used to migrate v1 "pbkdf2-sha256$iter$saltHex$hashHex" rows, whose hashHex
// is exactly SaltedPassword.
bool CredentialFromSaltedPassword(int iterations,
                                  const std::string& saltHex,
                                  const std::string& saltedPasswordHex,
                                  Credential& out);

// Parse a v1 "pbkdf2-sha256$iter$saltHex$hashHex" string into a credential.
bool CredentialFromV1Hash(const std::string& v1Hash, Credential& out);

// Validate and normalize (lowercase) individual fields, e.g. the values a
// client sends in [CHANGE2]. Applies the same rules as Parse().
bool CredentialFromParts(int iterations,
                         const std::string& saltHex,
                         const std::string& storedKeyHex,
                         const std::string& serverKeyHex,
                         Credential& out);

// "scram-sha256$<iter>$<saltHex>$<storedKeyHex>$<serverKeyHex>".
// Returns "" if the credential is invalid.
std::string Serialize(const Credential& credential);
bool Parse(const std::string& serialized, Credential& out);
// True if the string starts with "scram-sha256$" (cheap format sniffing).
bool IsScramCredentialString(const std::string& value);

// Validation helpers for wire fields.
bool IsValidIterations(int iterations);
bool IsValidSaltHex(const std::string& saltHex);           // 16..64 bytes, hex
bool IsHexString(const std::string& value, std::size_t exactHexChars);  // 0 = any even, non-empty length

// "river-auth-v2|user|hwid|clientNonce|combinedNonce|saltHex|iter".
// Returns "" if any field is empty or contains '|' (would make the message
// ambiguous) or iterations is invalid.
std::string BuildAuthMessage(const std::string& user,
                             const std::string& hwid,
                             const std::string& clientNonceHex,
                             const std::string& combinedNonceHex,
                             const std::string& saltHex,
                             int iterations);

// Client side. Outputs ClientProof (32 raw bytes) and the ServerSignature
// (32 raw bytes) the server must answer with. Refuses iterations outside
// [kMinIterations, kMaxIterations].
bool ComputeClientProof(const std::string& password,
                        const std::string& saltHex,
                        int iterations,
                        const std::string& authMessage,
                        std::string& clientProofRaw,
                        std::string& expectedServerSignatureRaw);

// Client side: constant-time comparison of the server's AUTH_OK signature.
bool VerifyServerSignature(const std::string& expectedServerSignatureRaw,
                           const std::string& receivedServerSignatureRaw);

// Server side: SHA256(ClientProof XOR HMAC(StoredKey, AuthMessage)) == StoredKey.
bool VerifyClientProof(const Credential& credential,
                       const std::string& authMessage,
                       const std::string& clientProofRaw);

// Server side: HMAC(ServerKey, AuthMessage), 32 raw bytes, or "" on error.
std::string ServerSignature(const Credential& credential, const std::string& authMessage);

// Lowercase hex of `bytes` random bytes ("" on RNG failure).
std::string RandomNonceHex(std::size_t bytes);

}  // namespace river::scram
