#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif
using SocketHandle = SOCKET;
inline constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using SocketHandle = int;
inline constexpr SocketHandle kInvalidSocket = -1;
#define closesocket close
#endif

#include <cstddef>
#include <cstdint>
#include <string>

inline constexpr std::uint16_t kFrameTypeText = 1;
inline constexpr std::uint16_t kFrameTypeAttachmentChunk = 2;

inline bool IsSocketValid(SocketHandle sock) {
    return sock != kInvalidSocket;
}

inline void CloseSocketHandle(SocketHandle sock) {
    if (!IsSocketValid(sock)) return;
#ifdef _WIN32
    shutdown(sock, SD_BOTH);
#else
    shutdown(sock, SHUT_RDWR);
#endif
    closesocket(sock);
}

bool SendAll(SocketHandle sock, const char* data, std::size_t size);
bool SendLine(SocketHandle sock, const std::string& line);
bool RecvExact(SocketHandle sock, char* data, std::size_t size);
bool SendFrame(SocketHandle sock, std::uint16_t type, const std::string& payload);
bool RecvFrame(SocketHandle sock, std::uint16_t& type, std::string& payload, std::size_t maxPayloadBytes);

// SendAll / RecvExact / RecvFrame restart send()/recv() interrupted by a signal
// (EINTR); a receive timeout (SO_RCVTIMEO) or a closed/broken link is a failure.

enum class RecvStatus {
    kOk,       // a whole frame was read
    kTimeout,  // SO_RCVTIMEO expired before the first byte of a frame: link idle, still usable
    kFailed,   // closed, broken, malformed or stalled in the middle of a frame
};
// RecvFrame for callers that treat an idle link as normal (the client): an
// expiry before a frame starts is kTimeout. Once a frame has started, up to
// allowedMidFrameTimeouts expiries are waited out before giving up.
RecvStatus RecvFrameOrTimeout(SocketHandle sock, std::uint16_t& type, std::string& payload,
                              std::size_t maxPayloadBytes, int allowedMidFrameTimeouts = 2);

// TCP socket that is not inherited by child processes (SOCK_CLOEXEC /
// FD_CLOEXEC; non-inheritable handle on Windows), so helpers the client runs
// (file pickers, openers) never hold a copy of the link.
SocketHandle CreateTcpSocket();
bool SetSocketCloseOnExec(SocketHandle sock);
bool SendTextFrame(SocketHandle sock, const std::string& payload);
bool RecvTextFrame(SocketHandle sock, std::string& payload, std::size_t maxPayloadBytes);
