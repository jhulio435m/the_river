#pragma once

#include <string>

#include "common/net_platform.h"

struct TorEndpoint {
    std::string proxyIp;
    int proxyPort;
    std::string onionAddress;
    unsigned short onionPort;
};

// Intenta conectar a un hidden service a través de Tor
SocketHandle ConnectViaTor(const TorEndpoint& endpoint, int recvTimeoutSeconds = 30);
bool IsTorProxyReachable(const std::string& ip, int port);

// GESTIÓN AUTOMÁTICA DE TOR
// Inicia el binario de Tor local si no hay un proxy activo
bool EnsureLocalTorIsRunning();
// Detiene el proceso Tor iniciado por la aplicación
void TerminateLocalTor();
