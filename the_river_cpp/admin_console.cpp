#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <sstream>
#include <cstring>
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define close closesocket
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif
#include "include/aes.h"

// --- CONFIGURACIÓN ADMIN ---
std::string ONION_ADDR = "3k4kzzkhiy6oyitin3g3wuy7hs6sf7tmcqdipe2vwaqxfyiggedltiid.onion";
std::string PROXY_IP = "127.0.0.1";
int PROXY_PORT = 9050;
const std::string AES_KEY = "RIVER_SECURE_KEY_2026_X";
const std::string AES_IV = "IV_VECTOR_091234";

int g_AdminSocket = -1;

bool ConnectTor() {
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
    g_AdminSocket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PROXY_PORT);
    inet_pton(AF_INET, PROXY_IP.c_str(), &addr.sin_addr);

    if (connect(g_AdminSocket, (struct sockaddr*)&addr, sizeof(addr)) != 0) return false;

    char hello[] = {0x05, 0x01, 0x00};
    send(g_AdminSocket, hello, 3, 0);
    char res[2]; recv(g_AdminSocket, res, 2, 0);

    std::vector<char> req = {0x05, 0x01, 0x00, 0x03};
    req.push_back((char)ONION_ADDR.length());
    for(char c : ONION_ADDR) req.push_back(c);
    req.push_back(0x00); req.push_back(0x50); 

    send(g_AdminSocket, req.data(), req.size(), 0);
    char reply[10]; recv(g_AdminSocket, reply, 10, 0);

    return reply[1] == 0x00;
}

void Receiver() {
    char buf[4096];
    while (true) {
        int b = recv(g_AdminSocket, buf, 4095, 0);
        if (b <= 0) break;
        buf[b] = '\0';
        
        std::string msg(buf);
        if (msg.find(":") != std::string::npos && msg.find("SYSTEM") == std::string::npos) {
            size_t sep = msg.find(":");
            std::string user = msg.substr(0, sep);
            std::string cipher = msg.substr(sep + 1);
            std::string decrypted = AESHelper::Decrypt(cipher, AES_KEY, AES_IV);
            std::cout << "\r\033[K[" << user << "]: " << decrypted << "\nADMIN> " << std::flush;
        } else {
            std::cout << "\r\033[K" << msg << "ADMIN> " << std::flush;
        }
    }
}

int main() {
    std::cout << "--- THE RIVER | ADMIN CONSOLE V.09 ---" << std::endl;
    std::cout << "[*] Conectando a la red Tor..." << std::endl;

    if (!ConnectTor()) {
        std::cerr << "[!] Error: No se puede alcanzar el proxy Tor." << std::endl;
        return 1;
    }

    std::string login = "[LOGIN]:admin:river123\n";
    send(g_AdminSocket, login.c_str(), login.length(), 0);

    std::thread(Receiver).detach();

    std::string input;
    while (true) {
        std::cout << "ADMIN> ";
        std::getline(std::cin, input);
        if (input == "/exit") break;
        if (input.empty()) continue;

        std::string encrypted = AESHelper::Encrypt(input, AES_KEY, AES_IV);
        std::string payload = "OVERSEER:" + encrypted + "\n";
        send(g_AdminSocket, payload.c_str(), payload.length(), 0);
    }

    close(g_AdminSocket);
    return 0;
}
