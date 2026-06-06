#include "common/net_platform.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <string>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

namespace {

constexpr std::uint32_t kFrameMagic = 0x54525631;  // TRV1
constexpr std::size_t kFrameHeaderBytes = 10;
constexpr std::size_t kAbsoluteMaxPayloadBytes = 1024 * 1024;

void StoreU16(char* out, std::uint16_t value) {
    out[0] = static_cast<char>((value >> 8) & 0xff);
    out[1] = static_cast<char>(value & 0xff);
}

void StoreU32(char* out, std::uint32_t value) {
    out[0] = static_cast<char>((value >> 24) & 0xff);
    out[1] = static_cast<char>((value >> 16) & 0xff);
    out[2] = static_cast<char>((value >> 8) & 0xff);
    out[3] = static_cast<char>(value & 0xff);
}

std::uint16_t LoadU16(const char* in) {
    return static_cast<std::uint16_t>(
        (static_cast<unsigned char>(in[0]) << 8) |
        static_cast<unsigned char>(in[1]));
}

std::uint32_t LoadU32(const char* in) {
    return (static_cast<std::uint32_t>(static_cast<unsigned char>(in[0])) << 24) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(in[1])) << 16) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(in[2])) << 8) |
           static_cast<std::uint32_t>(static_cast<unsigned char>(in[3]));
}

}  // namespace

bool SendAll(SocketHandle sock, const char* data, std::size_t size) {
    if (!IsSocketValid(sock) || (data == nullptr && size > 0)) return false;

    std::size_t totalSent = 0;
    while (totalSent < size) {
        const std::size_t remaining = size - totalSent;
        const int chunkSize = static_cast<int>(std::min<std::size_t>(remaining, 64 * 1024));
#ifdef _WIN32
        int sent = send(sock,
                        data + totalSent,
                        chunkSize,
                        0);
#else
        int sent = send(sock,
                        data + totalSent,
                        chunkSize,
                        MSG_NOSIGNAL);
#endif
        if (sent <= 0) return false;
        totalSent += static_cast<std::size_t>(sent);
    }
    return true;
}

bool SendLine(SocketHandle sock, const std::string& line) {
    return SendTextFrame(sock, line);
}

bool RecvExact(SocketHandle sock, char* data, std::size_t size) {
    if (!IsSocketValid(sock) || (data == nullptr && size > 0)) return false;

    std::size_t totalRead = 0;
    while (totalRead < size) {
        int received = recv(sock,
                            data + totalRead,
                            static_cast<int>(size - totalRead),
                            0);
        if (received <= 0) return false;
        totalRead += static_cast<std::size_t>(received);
    }
    return true;
}

bool SendFrame(SocketHandle sock, std::uint16_t type, const std::string& payload) {
    if (payload.size() > kAbsoluteMaxPayloadBytes) return false;

    char header[kFrameHeaderBytes] = {};
    StoreU32(header, kFrameMagic);
    StoreU16(header + 4, type);
    StoreU32(header + 6, static_cast<std::uint32_t>(payload.size()));

    return SendAll(sock, header, sizeof(header)) &&
           (payload.empty() || SendAll(sock, payload.data(), payload.size()));
}

bool RecvFrame(SocketHandle sock, std::uint16_t& type, std::string& payload, std::size_t maxPayloadBytes) {
    payload.clear();
    type = 0;

    char header[kFrameHeaderBytes] = {};
    if (!RecvExact(sock, header, sizeof(header))) return false;

    const std::uint32_t magic = LoadU32(header);
    if (magic != kFrameMagic) return false;

    type = LoadU16(header + 4);
    const std::uint32_t length = LoadU32(header + 6);
    if (length > maxPayloadBytes || length > kAbsoluteMaxPayloadBytes) return false;

    payload.assign(length, '\0');
    return length == 0 || RecvExact(sock, payload.data(), payload.size());
}

bool SendTextFrame(SocketHandle sock, const std::string& payload) {
    return SendFrame(sock, kFrameTypeText, payload);
}

bool RecvTextFrame(SocketHandle sock, std::string& payload, std::size_t maxPayloadBytes) {
    std::uint16_t type = 0;
    if (!RecvFrame(sock, type, payload, maxPayloadBytes)) return false;
    return type == kFrameTypeText;
}
