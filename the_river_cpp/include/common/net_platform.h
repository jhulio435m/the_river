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
