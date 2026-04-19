#include <iostream>
#include <string>
#include <thread>

#include "common/security_utils.h"
#include "common/shared_config.h"
#include "common/tor_connection.h"
#include "include/aes.h"

namespace {

void SendLine(SocketHandle sock, const std::string& msg) {
    std::string full = msg + "\n";
    send(sock, full.c_str(), (int)full.size(), 0);
}

void ReceiverLoop(SocketHandle sock) {
    char buf[4096];
    std::string accum;
    while (true) {
        int bytes = recv(sock, buf, 4095, 0);
        if (bytes <= 0) break;
        buf[bytes] = '\0';
        accum += buf;

        size_t pos = 0;
        while ((pos = accum.find('\n')) != std::string::npos) {
            std::string line = accum.substr(0, pos);
            accum.erase(0, pos + 1);

            if (line == "PING") {
                SendLine(sock, "PONG");
                continue;
            }

            if (line.find("[[USERS]]:") == 0 || line.find("[USERS]:") == 0) {
                // Silenciar protocolos de usuarios en consola admin
                continue;
            }

            if (line.find("[PM]:") == 0) {
                std::string rest = line.substr(5);
                size_t sep = rest.find(':');
                std::string from = sep == std::string::npos ? rest : rest.substr(0, sep);
                std::string enc = sep == std::string::npos ? "" : rest.substr(sep + 1);
                std::string dec = AESHelper::Decrypt(enc, river::kAesKey, "");
                std::cout << "\r\033[K[PM de " << from << "]: " << dec << "\nADMIN> " << std::flush;
            } else if (line.find("SYSTEM") == std::string::npos && line.find(':') != std::string::npos) {
                size_t sep = line.find(':');
                std::string user = line.substr(0, sep);
                std::string enc = line.substr(sep + 1);
                std::string dec = AESHelper::Decrypt(enc, river::kAesKey, "");
                
                // Fallback si no es encriptado
                if (dec.find("[DECRYPT_ERR]") != std::string::npos) dec = enc;
                
                std::cout << "\r\033[K[" << user << "]: " << dec << "\nADMIN> " << std::flush;
            } else {
                std::cout << "\r\033[K" << line << "\nADMIN> " << std::flush;
            }
        }
    }

    std::cout << "\n[!] Conexion cerrada.\n";
}

}

int main() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    std::cout << "--- THE RIVER | ADMIN CONSOLE ---" << std::endl;

    std::string adminUser;
    std::string adminPass;
    std::cout << "ADMIN IDENT : ";
    std::getline(std::cin, adminUser);
    std::cout << "ADMIN KEY   : ";
    std::getline(std::cin, adminPass);

    TorEndpoint endpoint{
        river::kTorProxyIp,
        river::kTorProxyPort,
        river::kOnionAddress,
        (unsigned short)river::kTorOnionPort
    };

    std::cout << "[*] Conectando por Tor..." << std::endl;
    SocketHandle adminSocket = ConnectViaTor(endpoint);
    if (!IsSocketValid(adminSocket)) {
        std::cerr << "[!] Tor no disponible o conexion .onion rechazada. Saliendo." << std::endl;
        return 1;
    }

    std::string login = "[LOGIN]:" + adminUser + ":" + adminPass + ":" + MakeStableMachineId();
    SendLine(adminSocket, login);

    std::thread receiver(ReceiverLoop, adminSocket);

    std::string input;
    std::cout << "ADMIN> ";
    while (std::getline(std::cin, input)) {
        if (input == "/exit") break;
        if (input.empty()) {
            std::cout << "ADMIN> ";
            continue;
        }

        std::string enc = AESHelper::Encrypt(input, river::kAesKey, "");
        SendLine(adminSocket, adminUser + ":" + enc);
        std::cout << "ADMIN> ";
    }

    CloseSocketHandle(adminSocket);
    receiver.join();
    return 0;
}
