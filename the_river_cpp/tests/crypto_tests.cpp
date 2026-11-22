#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

#include "common/e2e_crypto.h"
#include "common/scram.h"
#include "common/security_utils.h"

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

namespace scram = river::scram;
namespace e2e = river::e2e;

std::string TempDir() {
    const char* t = std::getenv("TMPDIR");
    std::string base = (t != nullptr && t[0] != '\0') ? t : "/tmp";
#ifdef _WIN32
    const char* w = std::getenv("TEMP");
    if (w != nullptr && w[0] != '\0') base = w;
#endif
    return base;
}

std::string TempPath(const std::string& name) {
    return TempDir() + "/river_crypto_test_" + RandomHex(8) + "_" + name;
}

std::string MakeAuthMessage(const scram::Credential& c) {
    const std::string clientNonce = scram::RandomNonceHex(16);
    const std::string combined = clientNonce + scram::RandomNonceHex(16);
    assert(clientNonce.size() == 32 && combined.size() == 64);
    const std::string msg = scram::BuildAuthMessage("alice", "hwid0123", clientNonce, combined, c.saltHex, c.iterations);
    assert(!msg.empty());
    return msg;
}

void TestScramRoundTrip() {
    const std::string password = "correct-horse-battery";
    scram::Credential cred;
    assert(scram::MakeCredential(password, cred));
    assert(cred.iterations >= 210000);
    assert(cred.saltHex.size() == 32);
    assert(cred.storedKeyHex.size() == 64 && cred.serverKeyHex.size() == 64);

    const std::string auth = MakeAuthMessage(cred);
    assert(auth.rfind("river-auth-v2|alice|hwid0123|", 0) == 0);
    assert(auth.size() > 7 && auth.substr(auth.size() - 7) == "|210000");

    std::string proof;
    std::string expectedSig;
    assert(scram::ComputeClientProof(password, cred.saltHex, cred.iterations, auth, proof, expectedSig));
    assert(proof.size() == 32 && expectedSig.size() == 32);
    assert(scram::VerifyClientProof(cred, auth, proof));

    const std::string serverSig = scram::ServerSignature(cred, auth);
    assert(serverSig.size() == 32);
    assert(scram::VerifyServerSignature(expectedSig, serverSig));
    std::string badSig = serverSig;
    badSig[0] ^= 1;
    assert(!scram::VerifyServerSignature(expectedSig, badSig));
    assert(!scram::VerifyServerSignature(expectedSig, ""));

    // Wrong password.
    std::string wrongProof;
    std::string wrongSig;
    assert(scram::ComputeClientProof("wrong-password-xx", cred.saltHex, cred.iterations, auth, wrongProof, wrongSig));
    assert(!scram::VerifyClientProof(cred, auth, wrongProof));
    assert(!scram::VerifyServerSignature(wrongSig, serverSig));

    // Tampered auth message (e.g. replay with another combined nonce).
    std::string tampered = auth;
    tampered[tampered.size() - 1] = '1';
    assert(!scram::VerifyClientProof(cred, tampered, proof));
    assert(!scram::VerifyClientProof(cred, MakeAuthMessage(cred), proof));

    // Tampered proof / bad length.
    std::string badProof = proof;
    badProof[5] ^= 0x40;
    assert(!scram::VerifyClientProof(cred, auth, badProof));
    assert(!scram::VerifyClientProof(cred, auth, proof.substr(0, 31)));
    assert(!scram::VerifyClientProof(cred, auth, ""));

    // Downgrade protection: client refuses tiny iteration counts.
    std::string p2;
    std::string s2;
    assert(!scram::ComputeClientProof(password, cred.saltHex, 1, auth, p2, s2));
    assert(!scram::ComputeClientProof(password, cred.saltHex, 99999, auth, p2, s2));
    assert(!scram::ComputeClientProof(password, "zz", cred.iterations, auth, p2, s2));

    // AuthMessage rejects separators / empty fields.
    assert(scram::BuildAuthMessage("al|ice", "h", "n", "nn", cred.saltHex, cred.iterations).empty());
    assert(scram::BuildAuthMessage("alice", "", "n", "nn", cred.saltHex, cred.iterations).empty());
    assert(scram::BuildAuthMessage("alice", "h", "n", "nn", cred.saltHex, 5).empty());
}

void TestScramMigration() {
    const std::string password = "legacy-password-123";
    const std::string v1 = MakePasswordHash(password);
    assert(v1.rfind("pbkdf2-sha256$", 0) == 0);

    scram::Credential cred;
    assert(scram::CredentialFromV1Hash(v1, cred));
    const std::string auth = MakeAuthMessage(cred);
    std::string proof;
    std::string sig;
    assert(scram::ComputeClientProof(password, cred.saltHex, cred.iterations, auth, proof, sig));
    assert(scram::VerifyClientProof(cred, auth, proof));
    assert(scram::VerifyServerSignature(sig, scram::ServerSignature(cred, auth)));

    std::string wrongProof;
    assert(scram::ComputeClientProof("other-password-123", cred.saltHex, cred.iterations, auth, wrongProof, sig));
    assert(!scram::VerifyClientProof(cred, auth, wrongProof));

    // Malformed v1 strings.
    scram::Credential junk;
    assert(!scram::CredentialFromV1Hash("", junk));
    assert(!scram::CredentialFromV1Hash("pbkdf2-sha256$210000$abcd", junk));
    assert(!scram::CredentialFromV1Hash(v1 + "$extra", junk));
    assert(!scram::CredentialFromV1Hash("sha256$" + v1, junk));
    assert(!scram::CredentialFromSaltedPassword(210000, cred.saltHex, "00", junk));
}

void TestScramSerialize() {
    scram::Credential cred;
    assert(scram::MakeCredential("serialize-me-please", cred));
    const std::string s = scram::Serialize(cred);
    assert(s.rfind("scram-sha256$210000$", 0) == 0);
    assert(scram::IsScramCredentialString(s));

    scram::Credential back;
    assert(scram::Parse(s, back));
    assert(back.iterations == cred.iterations);
    assert(back.saltHex == cred.saltHex);
    assert(back.storedKeyHex == cred.storedKeyHex);
    assert(back.serverKeyHex == cred.serverKeyHex);
    assert(scram::Serialize(back) == s);

    // Uppercase hex is normalized.
    std::string upper = s;
    for (std::size_t i = std::string("scram-sha256$").size(); i < upper.size(); ++i) {
        if (upper[i] >= 'a' && upper[i] <= 'f') upper[i] = static_cast<char>(upper[i] - 'a' + 'A');
    }
    assert(scram::Parse(upper, back));
    assert(scram::Serialize(back) == s);

    const std::string salt = cred.saltHex;
    const std::string sk = cred.storedKeyHex;
    const std::string vk = cred.serverKeyHex;
    const std::string bad[] = {
        "",
        "scram-sha256$",
        "scram-sha256$210000$" + salt + "$" + sk,
        "scram-sha256$210000$" + salt + "$" + sk + "$" + vk + "$",
        "scram-sha256$210000$" + salt + "$" + sk + "$" + vk + "$x",
        "scram-sha256$abc$" + salt + "$" + sk + "$" + vk,
        "scram-sha256$-210000$" + salt + "$" + sk + "$" + vk,
        "scram-sha256$0210000$" + salt + "$" + sk + "$" + vk,
        "scram-sha256$99999$" + salt + "$" + sk + "$" + vk,
        "scram-sha256$999999999$" + salt + "$" + sk + "$" + vk,
        "scram-sha256$210000$$" + sk + "$" + vk,
        "scram-sha256$210000$abcd$" + sk + "$" + vk,
        "scram-sha256$210000$" + salt + "$" + sk.substr(2) + "$" + vk,
        "scram-sha256$210000$" + salt + "$" + sk + "$" + vk + "00",
        "scram-sha256$210000$" + salt + "$" + sk + "$" + vk.substr(0, 63) + "g",
        "SCRAM-SHA256$210000$" + salt + "$" + sk + "$" + vk,
        "pbkdf2-sha256$210000$" + salt + "$" + sk,
    };
    for (const std::string& b : bad) {
        scram::Credential c;
        assert(!scram::Parse(b, c));
    }

    scram::Credential invalid;
    assert(scram::Serialize(invalid).empty());

    scram::Credential parts;
    assert(scram::CredentialFromParts(150000, salt, sk, vk, parts));
    assert(!scram::CredentialFromParts(150000, salt, sk, "", parts));
}

void TestFingerprint() {
    e2e::KeyPair kp;
    assert(e2e::GenerateKeyPair(kp));
    const std::string fp = e2e::Fingerprint(kp.pub32);
    assert(fp.size() == 39);
    for (std::size_t i = 0; i < fp.size(); ++i) {
        if (i % 5 == 4) {
            assert(fp[i] == '-');
        } else {
            assert((fp[i] >= '0' && fp[i] <= '9') || (fp[i] >= 'a' && fp[i] <= 'f'));
        }
    }
    assert(e2e::Fingerprint(kp.pub32) == fp);
    assert(e2e::Fingerprint(std::string(kp.pub32)) == fp);
    // Known vector: SHA256 of 32 zero bytes = 66687aadf862bd776c8fc18b8e9f8e20...
    assert(e2e::Fingerprint(std::string(32, '\0')) == "6668-7aad-f862-bd77-6c8f-c18b-8e9f-8e20");
    e2e::KeyPair other;
    assert(e2e::GenerateKeyPair(other));
    assert(e2e::Fingerprint(other.pub32) != fp);
    assert(e2e::Fingerprint("short").empty());
}

void TestKeyPair() {
    e2e::KeyPair kp;
    assert(e2e::GenerateKeyPair(kp));
    assert(kp.priv32.size() == 32 && kp.pub32.size() == 32);
    std::string pub;
    assert(e2e::PublicFromPrivate(kp.priv32, pub));
    assert(pub == kp.pub32);
    assert(e2e::IsValidKeyPair(kp));
    assert(!e2e::PublicFromPrivate("x", pub));

    // RFC 7748 section 6.1 vector (Alice).
    const unsigned char alicePriv[32] = {0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
                                         0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
                                         0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a};
    const unsigned char alicePub[32] = {0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d,
                                        0xdc, 0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38,
                                        0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a};
    assert(e2e::PublicFromPrivate(std::string(reinterpret_cast<const char*>(alicePriv), 32), pub));
    assert(pub == std::string(reinterpret_cast<const char*>(alicePub), 32));

    e2e::KeyPair mismatched;
    mismatched.priv32 = kp.priv32;
    assert(e2e::GenerateKeyPair(mismatched) && e2e::IsValidKeyPair(mismatched));
    mismatched.pub32 = kp.pub32;
    assert(!e2e::IsValidKeyPair(mismatched));
    e2e::Clear(mismatched);
    assert(mismatched.priv32.empty() && mismatched.pub32.empty());
}

void TestE2E() {
    e2e::KeyPair alice;
    e2e::KeyPair bob;
    e2e::KeyPair eve;
    assert(e2e::GenerateKeyPair(alice) && e2e::GenerateKeyPair(bob) && e2e::GenerateKeyPair(eve));

    const std::string msg = "hola bob, esto es privado";
    std::string env;
    assert(e2e::Seal(alice, bob.pub32, "pm", "alice", "bob", msg, env));
    assert(env.size() == e2e::kEnvelopeOverhead + msg.size());
    assert(env.compare(0, 3, "RE2") == 0 && env[3] == 1);

    std::string out;
    assert(e2e::Open(bob, alice.pub32, "pm", "alice", "bob", env, out));
    assert(out == msg);

    // Two seals of the same message differ (ephemeral key + nonce).
    std::string env2;
    assert(e2e::Seal(alice, bob.pub32, "pm", "alice", "bob", msg, env2));
    assert(env2 != env);

    // Wrong recipient key, wrong sender pub.
    assert(!e2e::Open(eve, alice.pub32, "pm", "alice", "bob", env, out));
    assert(out.empty());
    assert(!e2e::Open(bob, eve.pub32, "pm", "alice", "bob", env, out));
    // Sender cannot open its own envelope (no recipient priv).
    assert(!e2e::Open(alice, alice.pub32, "pm", "alice", "bob", env, out));

    // Wrong context / fromUser / toUser.
    assert(!e2e::Open(bob, alice.pub32, "att:1", "alice", "bob", env, out));
    assert(!e2e::Open(bob, alice.pub32, "pm", "mallory", "bob", env, out));
    assert(!e2e::Open(bob, alice.pub32, "pm", "alice", "bobby", env, out));
    assert(!e2e::Open(bob, alice.pub32, "pm", "bob", "alice", env, out));

    // Tamper each byte.
    for (std::size_t i = 0; i < env.size(); ++i) {
        std::string t = env;
        t[i] = static_cast<char>(t[i] ^ 0x01);
        assert(!e2e::Open(bob, alice.pub32, "pm", "alice", "bob", t, out));
    }
    // Truncation / extension.
    assert(!e2e::Open(bob, alice.pub32, "pm", "alice", "bob", env.substr(0, env.size() - 1), out));
    assert(!e2e::Open(bob, alice.pub32, "pm", "alice", "bob", env + "x", out));
    assert(!e2e::Open(bob, alice.pub32, "pm", "alice", "bob", env.substr(0, 63), out));
    assert(!e2e::Open(bob, alice.pub32, "pm", "alice", "bob", "", out));

    // Empty plaintext.
    assert(e2e::Seal(alice, bob.pub32, "pm", "alice", "bob", "", env));
    assert(env.size() == e2e::kEnvelopeOverhead);
    out = "garbage";
    assert(e2e::Open(bob, alice.pub32, "pm", "alice", "bob", env, out));
    assert(out.empty());

    // 32 KiB binary plaintext, attachment context.
    std::string big(32 * 1024, '\0');
    for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<char>((i * 131 + 7) & 0xff);
    assert(e2e::Seal(alice, bob.pub32, "att:abc123", "alice", "bob", big, env));
    assert(e2e::Open(bob, alice.pub32, "att:abc123", "alice", "bob", env, out));
    assert(out == big);
    assert(!e2e::Open(bob, alice.pub32, "att:abc124", "alice", "bob", env, out));

    // Invalid labels / keys.
    assert(!e2e::Seal(alice, bob.pub32, "", "alice", "bob", msg, env));
    assert(!e2e::Seal(alice, bob.pub32, "pm|x", "alice", "bob", msg, env));
    assert(!e2e::Seal(alice, bob.pub32, "pm", "al|ice", "bob", msg, env));
    assert(!e2e::Seal(alice, "short", "pm", "alice", "bob", msg, env));
    // Low-order (all zero) recipient public key is rejected.
    assert(!e2e::Seal(alice, std::string(32, '\0'), "pm", "alice", "bob", msg, env));
    e2e::KeyPair empty;
    assert(!e2e::Seal(empty, bob.pub32, "pm", "alice", "bob", msg, env));
}

void TestIdentityFile() {
    e2e::KeyPair kp;
    assert(e2e::GenerateKeyPair(kp));
    assert(e2e::IdentityFileName("alice") == "river_identity_alice.key");
    assert(e2e::IdentityFileName("../x").empty());

    const std::string path = TempPath(e2e::IdentityFileName("alice"));
    const std::string password = "identity-password-1";
    assert(e2e::SaveIdentity(path, kp, password));

    {
        std::ifstream in(path, std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        assert(content.size() == 80);
        assert(content.compare(0, 4, "RIK1") == 0);
        assert(content.find(kp.priv32) == std::string::npos);
    }

#ifndef _WIN32
    struct stat st {};
    assert(stat(path.c_str(), &st) == 0);
    assert((st.st_mode & 0777) == 0600);
#endif

    e2e::KeyPair loaded;
    assert(e2e::LoadIdentity(path, password, loaded));
    assert(loaded.priv32 == kp.priv32 && loaded.pub32 == kp.pub32);

    e2e::KeyPair bad;
    assert(!e2e::LoadIdentity(path, "wrong-password-1", bad));
    assert(bad.priv32.empty());
    assert(!e2e::LoadIdentity(path + ".missing", password, bad));

    // Re-encrypt with a new password (overwrite in place).
    assert(e2e::SaveIdentity(path, kp, "new-password-2345"));
    assert(!e2e::LoadIdentity(path, password, bad));
    assert(e2e::LoadIdentity(path, "new-password-2345", loaded));
    assert(loaded.priv32 == kp.priv32);
#ifndef _WIN32
    assert(stat(path.c_str(), &st) == 0);
    assert((st.st_mode & 0777) == 0600);
#endif

    // Tampered / truncated file.
    {
        std::ifstream in(path, std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();
        content[40] ^= 0x01;
        std::ofstream o(path, std::ios::binary | std::ios::trunc);
        o.write(content.data(), static_cast<std::streamsize>(content.size()));
        o.close();
        assert(!e2e::LoadIdentity(path, "new-password-2345", bad));
        std::ofstream o2(path, std::ios::binary | std::ios::trunc);
        o2.write(content.data(), 79);
        o2.close();
        assert(!e2e::LoadIdentity(path, "new-password-2345", bad));
    }

    // Invalid key pair is not saved.
    e2e::KeyPair broken;
    broken.priv32 = kp.priv32;
    broken.pub32 = std::string(32, 'x');
    const std::string path2 = TempPath("broken.key");
    assert(!e2e::SaveIdentity(path2, broken, password));
    assert(!e2e::SaveIdentity(path2, kp, ""));

    std::remove(path.c_str());
    std::remove(path2.c_str());
}

}  // namespace

int main() {
    TestScramRoundTrip();
    TestScramMigration();
    TestScramSerialize();
    TestFingerprint();
    TestKeyPair();
    TestE2E();
    TestIdentityFile();
    std::cout << "crypto tests passed\n";
    return 0;
}
