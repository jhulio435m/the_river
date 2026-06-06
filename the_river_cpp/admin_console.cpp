#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <chrono>

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#include "common/security_utils.h"
#include "common/secure_envelope.h"
#include "common/shared_config.h"
#include "common/tor_connection.h"

namespace {

void ClearScreen() {
    std::cout << "\033[2J\033[H";
}

void Typewriter(const std::string& text, int delay_ms = 20) {
    for (char c : text) {
        std::cout << c << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }
    std::cout << std::endl;
}

void DrawLogo() {
    std::cout << "\033[1;32m";
    std::cout << R"(
  _______ _    _ ______   _____  _______      ________ _____
 |__   __| |  | |  ____| |  __ \|_   _\ \    / /  ____|  __ \
    | |  | |__| | |__    | |__) | | |  \ \  / /| |__  | |__) |
    | |  |  __  |  __|   |  _  /  | |   \ \/ / |  __| |  _  /
    | |  | |  | | |____  | | \ \ _| |_   \  /  | |____| | \ \
    |_|  |_|  |_|______| |_|  \_\\_____|   \/   |______|_|  \_/
    )" << "\n";
    std::cout << "  [ THE RIVER SECURE ADMINISTRATION TERMINAL v2.0 ]\n";
    std::cout << "\033[0m" << std::endl;
}

void BootAnimation() {
    ClearScreen();
    DrawLogo();
    std::cout << "\033[1;32m";
    Typewriter("[*] INITIALIZING CORE MODULES...", 30);
    Typewriter("[*] LOADING RSA/AES CRYPTO HANDLERS...", 30);
    Typewriter("[*] ESTABLISHING SOCKS5 PROXY LINK...", 50);
    Typewriter("[*] TUNNELING THROUGH ONION NETWORK...", 80);
    std::cout << "\033[0m\n";
}

void SendAdminLine(SocketHandle sock, const std::string& msg) {
    ::SendLine(sock, msg);
}

bool ReadProtocolLine(SocketHandle sock, std::string& line) {
    return RecvTextFrame(sock, line, 65536);
}

std::vector<std::string> SplitWhitespace(const std::string& input) {
    std::stringstream ss(input);
    std::vector<std::string> parts;
    std::string part;
    while (ss >> part) parts.push_back(part);
    return parts;
}

std::string DecryptWirePayload(const std::string& payload) {
    std::string plain;
    if (!river::OpenPayload(payload, plain)) return "[AUTH_ERR]";
    return plain;
}

std::string ReadSecretLine() {
#ifdef _WIN32
    std::string value;
    while (true) {
        int c = _getch();
        if (c == '\r' || c == '\n') {
            std::cout << std::endl;
            break;
        }
        if ((c == '\b' || c == 127) && !value.empty()) {
            value.pop_back();
            continue;
        }
        if (c >= 32) value.push_back(static_cast<char>(c));
    }
    return value;
#else
    termios oldTerm{};
    termios newTerm{};
    if (tcgetattr(STDIN_FILENO, &oldTerm) != 0) {
        std::string fallback;
        std::getline(std::cin, fallback);
        return fallback;
    }

    newTerm = oldTerm;
    newTerm.c_lflag &= static_cast<unsigned int>(~ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newTerm);
    std::string value;
    std::getline(std::cin, value);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldTerm);
    std::cout << std::endl;
    return value;
#endif
}

void ReceiverLoop(SocketHandle sock) {
    while (true) {
        std::string line;
        if (!RecvTextFrame(sock, line, 65536)) break;

        if (line == "PING") {
            SendAdminLine(sock, "PONG");
            continue;
        }

        if (line.rfind("[[USERS]]:", 0) == 0 || line.rfind("[USERS]:", 0) == 0) {
            continue;
        }
        if (line.rfind("SESSION:", 0) == 0) {
            continue;
        }

        std::cout << "\r\033[K"; // Clear current line
        if (line.rfind("[PM]:", 0) == 0) {
            std::string rest = line.substr(5);
            size_t sep = rest.find(':');
            std::string from = sep == std::string::npos ? rest : rest.substr(0, sep);
            std::string enc = sep == std::string::npos ? "" : rest.substr(sep + 1);
            std::string dec = DecryptWirePayload(enc);
            std::cout << "\033[1;33m[PM de " << from << "]:\033[0m " << dec << "\n\033[1;32mADMIN>\033[0m " << std::flush;
        } else if (line.find("SYSTEM") != std::string::npos) {
            std::cout << "\033[1;31m" << line << "\033[0m\n\033[1;32mADMIN>\033[0m " << std::flush;
        } else if (line.find(':') != std::string::npos) {
            size_t sep = line.find(':');
            std::string user = line.substr(0, sep);
            std::string enc = line.substr(sep + 1);
            std::string dec = DecryptWirePayload(enc);
            std::cout << "\033[1;36m[" << user << "]:\033[0m " << dec << "\n\033[1;32mADMIN>\033[0m " << std::flush;
        } else {
            std::cout << line << "\n\033[1;32mADMIN>\033[0m " << std::flush;
        }
    }

    std::cout << "\n\033[1;31m[!] CONEXION FINALIZADA POR EL SERVIDOR.\033[0m\n";
}

}

int main() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    BootAnimation();

    if (!river::HasRequiredClientConfig()) {
        std::cerr << "\033[1;31m[!] FATAL: Faltan variables de entorno (THE_RIVER_ONION / THE_RIVER_AES_KEY).\033[0m" << std::endl;
        return 1;
    }

    std::string adminUser;
    std::string adminPass;
    std::cout << "\033[1;32mIDENTIFICADOR DE ACCESO: \033[0m";
    std::getline(std::cin, adminUser);
    std::cout << "\033[1;32mCLAVE DE ENCRIPTACION : \033[0m";
    adminPass = ReadSecretLine();

    TorEndpoint endpoint{
        river::kTorProxyIp,
        river::kTorProxyPort,
        river::OnionAddress(),
        (unsigned short)river::kTorOnionPort
    };

    std::cout << "\033[1;32m[*] CONECTANDO AL NODO ONION...\033[0m" << std::endl;
    SocketHandle adminSocket = ConnectViaTor(endpoint);
    if (!IsSocketValid(adminSocket)) {
        std::cerr << "\033[1;31m[!] ERROR: Tor no responde o la direccion .onion es inaccesible.\033[0m" << std::endl;
        return 1;
    }

    const std::string hwid = MakeStableMachineId();
    SendAdminLine(adminSocket, "[LOGIN_INIT]:" + adminUser + ":" + hwid);
    
    std::string challenge;
    bool gotChallenge = false;
    for (int i = 0; i < 5; ++i) {
        if (!ReadProtocolLine(adminSocket, challenge)) break;
        if (challenge.rfind("AUTH_CHALLENGE:", 0) == 0) {
            gotChallenge = true;
            break;
        }
    }

    if (!gotChallenge) {
        std::cerr << "\033[1;31m[!] ERROR: El servidor no ha emitido un reto de autenticacion.\033[0m" << std::endl;
        CloseSocketHandle(adminSocket);
        return 1;
    }

    std::vector<std::string> challengeParts;
    {
        std::stringstream ss(challenge);
        std::string part;
        while (std::getline(ss, part, ':')) challengeParts.push_back(part);
    }

    if (challengeParts.size() < 3) {
        std::cerr << "\033[1;31m[!] ERROR: Reto corrupto o incompatible.\033[0m" << std::endl;
        CloseSocketHandle(adminSocket);
        return 1;
    }

    const std::string verifier = DerivePasswordVerifier(adminPass, challengeParts[2]);
    if (verifier.empty()) {
        std::cerr << "\033[1;31m[!] ERROR: Derivacion de clave fallida.\033[0m" << std::endl;
        CloseSocketHandle(adminSocket);
        return 1;
    }
    const std::string proof = HmacSha256Hex(verifier, challengeParts[1] + "|" + adminUser + "|" + hwid);
    SendAdminLine(adminSocket, "[LOGIN_PROOF]:" + adminUser + ":" + hwid + ":" + proof);

    std::thread receiver(ReceiverLoop, adminSocket);

    std::string input;
    std::cout << "\033[1;32mADMIN>\033[0m ";
    while (std::getline(std::cin, input)) {
        if (input == "/exit" || input == "/quit") break;
        if (input.empty()) {
            std::cout << "\033[1;32mADMIN>\033[0m ";
            continue;
        }

        if (input == "/clear") {
            ClearScreen();
            DrawLogo();
            std::cout << "\033[1;32mADMIN>\033[0m ";
            continue;
        }

        std::vector<std::string> parts = SplitWhitespace(input);
        if (parts.size() == 2 && parts[0] == "/passwd") {
            std::cout << "\033[1;33mNUEVA CLAVE PARA " << parts[1] << ": \033[0m";
            const std::string newPass = ReadSecretLine();
            input = "/passwd " + parts[1] + " " + newPass;
        }

        std::string enc = river::SealPayload(input);
        SendAdminLine(adminSocket, adminUser + ":" + enc);
        std::cout << "\033[1;32mADMIN>\033[0m ";
    }

    std::cout << "\033[1;32m[*] CERRANDO SESION SEGURA...\033[0m\n";
    CloseSocketHandle(adminSocket);
    if (receiver.joinable()) receiver.join();
    return 0;
}
