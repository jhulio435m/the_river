#include <cassert>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "common/base64.h"
#include "common/secure_envelope.h"
#include "common/security_utils.h"

namespace {

void TestBase64RoundTrip() {
    const std::string input = "The River payload 123";
    const std::string encoded = river::base64::EncodeString(input);

    std::string decoded;
    assert(river::base64::DecodeToString(encoded, decoded));
    assert(decoded == input);
}

void TestSha256Vector() {
    assert(HashPassword("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

void TestPasswordHashRoundTrip() {
    const std::string password = "correct-horse-key";
    const std::string storedHash = MakePasswordHash(password);

    assert(storedHash.rfind("pbkdf2-sha256$", 0) == 0);
    assert(VerifyPasswordHash(password, storedHash));
    assert(!VerifyPasswordHash("wrong-password", storedHash));
}

void TestPasswordVerifier() {
    const std::string password = "another-good-key";
    const std::string storedHash = MakePasswordHash(password);
    const std::vector<std::string> parts = {
        storedHash.substr(0, storedHash.rfind('$'))
    };

    const std::string verifier = DerivePasswordVerifier(password, parts[0]);
    assert(!verifier.empty());
    assert(verifier == storedHash);
}

void TestValidationRules() {
    assert(IsValidUsername("admin_01"));
    assert(!IsValidUsername("ab"));
    assert(!IsValidUsername("bad:name"));

    assert(IsStrongEnoughPassword("twelve-chars1"));
    assert(!IsStrongEnoughPassword("ten-chars1"));
    assert(!IsStrongEnoughPassword("invalid:separator"));
    assert(ConstantTimeEquals("abcdef", "abcdef"));
    assert(!ConstantTimeEquals("abcdef", "abcdeg"));
}

void TestSecureEnvelopeRoundTrip() {
    setenv("THE_RIVER_AES_KEY", "unit-test-key-with-enough-entropy", 1);

    const std::string plainText = "private message body";
    const std::string sealed = river::SealPayload(plainText);
    assert(sealed.rfind("v3|", 0) == 0);

    std::string opened;
    assert(river::OpenPayload(sealed, opened));
    assert(opened == plainText);

    std::string tampered = sealed;
    tampered.back() = tampered.back() == 'A' ? 'B' : 'A';
    assert(!river::OpenPayload(tampered, opened));
}

}  // namespace

int main() {
    TestBase64RoundTrip();
    TestSha256Vector();
    TestPasswordHashRoundTrip();
    TestPasswordVerifier();
    TestValidationRules();
    TestSecureEnvelopeRoundTrip();

    std::cout << "river_unit_tests passed\n";
    return 0;
}
