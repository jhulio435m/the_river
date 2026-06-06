#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "common/base64.h"
#include "common/net_platform.h"
#include "common/secure_envelope.h"
#include "common/security_utils.h"

#ifndef _WIN32
#include <sys/socket.h>
#endif

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

    const std::string binaryPlain("abc\0def", 7);
    const std::string binarySealed = river::SealPayloadBinary(binaryPlain);
    assert(binarySealed.rfind("RV4", 0) == 0);
    std::string binaryOpened;
    assert(river::OpenPayloadBinary(binarySealed, binaryOpened));
    assert(binaryOpened == binaryPlain);
}

void TestBinaryFrameRoundTrip() {
#ifndef _WIN32
    int sockets[2] = {-1, -1};
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);

    const std::string payload = "frame payload without newline";
    const bool sent = SendTextFrame(sockets[0], payload);
    if (!sent && errno == EPERM) {
        std::cerr << "skipping frame socket test: send blocked by sandbox\n";
        CloseSocketHandle(sockets[0]);
        CloseSocketHandle(sockets[1]);
        return;
    }
    assert(sent);

    std::string received;
    assert(RecvTextFrame(sockets[1], received, 1024));
    assert(received == payload);

    const std::string binaryPayload("bin\0payload", 11);
    assert(SendFrame(sockets[0], kFrameTypeAttachmentChunk, binaryPayload));
    std::uint16_t frameType = 0;
    std::string framePayload;
    assert(RecvFrame(sockets[1], frameType, framePayload, 1024));
    assert(frameType == kFrameTypeAttachmentChunk);
    assert(framePayload == binaryPayload);

    CloseSocketHandle(sockets[0]);
    CloseSocketHandle(sockets[1]);
#endif
}

}  // namespace

int main() {
    TestBase64RoundTrip();
    TestSha256Vector();
    TestPasswordHashRoundTrip();
    TestPasswordVerifier();
    TestValidationRules();
    TestSecureEnvelopeRoundTrip();
    TestBinaryFrameRoundTrip();

    std::cout << "river_unit_tests passed\n";
    return 0;
}
