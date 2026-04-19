#include "common/tor_connection.h"

#include <cstdint>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

namespace {

std::mutex gTorLogMutex;

void AppendTorLog(const std::string& line) {
    std::lock_guard<std::mutex> lock(gTorLogMutex);
    std::ofstream out("tor_client_debug.log", std::ios::app);
    if (!out.is_open()) return;
    out << line << "\n";
}

bool RecvExact(SocketHandle sock, char* buffer, int totalBytes) {
    int received = 0;
    while (received < totalBytes) {
        int chunk = recv(sock, buffer + received, totalBytes - received, 0);
        if (chunk <= 0) {
#ifdef _WIN32
            AppendTorLog("RecvExact fail chunk=" + std::to_string(chunk) +
                         " wsa=" + std::to_string(WSAGetLastError()));
#else
            AppendTorLog("RecvExact fail chunk=" + std::to_string(chunk) +
                         " errno=" + std::to_string(errno));
#endif
            return false;
        }
        received += chunk;
    }
    return true;
}

}

#ifdef _WIN32
#include <windows.h>
#include <urlmon.h>
#include <direct.h>
#pragma comment(lib, "urlmon.lib")
#else
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#endif

namespace {

#ifdef _WIN32
HANDLE g_torProcessHandle = NULL;
#else
pid_t g_torPid = 0;
#endif

bool IsProxyListening(const std::string& ip, int port) {
    SocketHandle s = socket(AF_INET, SOCK_STREAM, 0);
    if (!IsSocketValid(s)) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    // Timeout corto para verificación
#ifdef _WIN32
    DWORD timeout = 500;
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#endif

    bool ok = (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    CloseSocketHandle(s);
    return ok;
}

}

bool EnsureLocalTorIsRunning() {
    if (IsProxyListening("127.0.0.1", 9050)) {
        AppendTorLog("Tor proxy already active on 9050.");
        return true;
    }

    AppendTorLog("Tor proxy not found. Initializing auto-deploy...");

#ifdef _WIN32
    const char* torFolder = "tor_bin";
    const char* torExe = "tor_bin\\tor.exe";
    _mkdir(torFolder);

    if (GetFileAttributesA(torExe) == INVALID_FILE_ATTRIBUTES) {
        AppendTorLog("Tor binary missing. Downloading bootstrap...");
        // URL de respaldo de binario Tor minimalista (ejemplo)
        const char* torUrl = "https://github.com/the-river-project/tor-static/releases/download/v1.0/tor.exe";
        HRESULT hr = URLDownloadToFileA(NULL, torUrl, torExe, 0, NULL);
        if (FAILED(hr)) {
            AppendTorLog("Bootstrap download failed. HRESULT=" + std::to_string(hr));
            return false;
        }
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // Ejecución invisible

    std::string cmd = std::string(torExe) + " --socksport 9050 --DataDirectory tor_data";
    if (CreateProcessA(NULL, (char*)cmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        g_torProcessHandle = pi.hProcess;
        CloseHandle(pi.hThread);
        AppendTorLog("Local Tor process started invisibly.");
        return true;
    }
#else
    // Lógica similar para Linux usando fork/exec
    AppendTorLog("Auto-deploy for Linux not yet implemented in this build.");
#endif

    return false;
}

void TerminateLocalTor() {
#ifdef _WIN32
    if (g_torProcessHandle) {
        TerminateProcess(g_torProcessHandle, 0);
        CloseHandle(g_torProcessHandle);
        g_torProcessHandle = NULL;
        AppendTorLog("Local Tor process terminated.");
    }
#endif
}

SocketHandle ConnectViaTor(const TorEndpoint& endpoint, int recvTimeoutSeconds) {
    AppendTorLog("ConnectViaTor begin onion=" + endpoint.onionAddress +
                 " proxy=" + endpoint.proxyIp + ":" + std::to_string(endpoint.proxyPort));
    SocketHandle sock = socket(AF_INET, SOCK_STREAM, 0);
    if (!IsSocketValid(sock)) {
        AppendTorLog("socket() invalid");
        return kInvalidSocket;
    }

#ifdef _WIN32
    DWORD timeoutMs = static_cast<DWORD>(recvTimeoutSeconds * 1000);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
#else
    struct timeval tv{recvTimeoutSeconds, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(endpoint.proxyPort);
    inet_pton(AF_INET, endpoint.proxyIp.c_str(), &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
#ifdef _WIN32
        AppendTorLog("connect(proxy) failed wsa=" + std::to_string(WSAGetLastError()));
#else
        AppendTorLog("connect(proxy) failed errno=" + std::to_string(errno));
#endif
        CloseSocketHandle(sock);
        return kInvalidSocket;
    }
    AppendTorLog("connect(proxy) ok");

    char hello[] = {0x05, 0x01, 0x00};
    if (send(sock, hello, 3, 0) != 3) {
        AppendTorLog("send(hello) failed");
        CloseSocketHandle(sock);
        return kInvalidSocket;
    }
    AppendTorLog("send(hello) ok");

    char greetingReply[2];
    if (!RecvExact(sock, greetingReply, 2) || greetingReply[1] != 0x00) {
        AppendTorLog("greeting reply failed ver=" +
                     std::to_string((unsigned char)greetingReply[0]) +
                     " method=" + std::to_string((unsigned char)greetingReply[1]));
        CloseSocketHandle(sock);
        return kInvalidSocket;
    }
    AppendTorLog("greeting reply ok");

    std::vector<char> request = {0x05, 0x01, 0x00, 0x03};
    request.push_back((char)endpoint.onionAddress.size());
    for (char c : endpoint.onionAddress) request.push_back(c);
    request.push_back((char)((endpoint.onionPort >> 8) & 0xFF));
    request.push_back((char)(endpoint.onionPort & 0xFF));
    if (send(sock, request.data(), (int)request.size(), 0) != (int)request.size()) {
        AppendTorLog("send(connect request) failed");
        CloseSocketHandle(sock);
        return kInvalidSocket;
    }
    AppendTorLog("send(connect request) ok");

    char replyHead[4];
    if (!RecvExact(sock, replyHead, 4) || replyHead[1] != 0x00) {
        AppendTorLog("connect reply failed ver=" +
                     std::to_string((unsigned char)replyHead[0]) +
                     " rep=" + std::to_string((unsigned char)replyHead[1]) +
                     " atyp=" + std::to_string((unsigned char)replyHead[3]));
        CloseSocketHandle(sock);
        return kInvalidSocket;
    }
    AppendTorLog("connect reply head ok atyp=" + std::to_string((unsigned char)replyHead[3]));

    int addrBytes = 0;
    unsigned char atyp = static_cast<unsigned char>(replyHead[3]);
    if (atyp == 0x01) {
        addrBytes = 4;
    } else if (atyp == 0x03) {
        char domainLen = 0;
        if (!RecvExact(sock, &domainLen, 1)) {
            AppendTorLog("recv(domain len) failed");
            CloseSocketHandle(sock);
            return kInvalidSocket;
        }
        addrBytes = static_cast<unsigned char>(domainLen);
        AppendTorLog("domain len=" + std::to_string(addrBytes));
    } else if (atyp == 0x04) {
        addrBytes = 16;
    } else {
        AppendTorLog("unsupported atyp=" + std::to_string(atyp));
        CloseSocketHandle(sock);
        return kInvalidSocket;
    }

    std::vector<char> tail(addrBytes + 2);
    if (!tail.empty() && !RecvExact(sock, tail.data(), (int)tail.size())) {
        AppendTorLog("recv(reply tail) failed bytes=" + std::to_string((int)tail.size()));
        CloseSocketHandle(sock);
        return kInvalidSocket;
    }

    AppendTorLog("ConnectViaTor success");
    return sock;
}
