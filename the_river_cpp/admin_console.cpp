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

#include "common/base64.h"
#include "common/scram.h"
#include "common/security_utils.h"
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

std::string DecodeTextB64(const std::string& payload) {
    std::string plain;
    if (!river::base64::DecodeToString(payload, plain)) return "[mensaje ilegible]";
    return plain;
}

// "<from>:<unixTs>:<payload>" (after "MSG:", "HIST:", "PM2:").
bool SplitSenderTsPayload(const std::string& rest, std::string& from, std::string& payload) {
    const std::size_t first = rest.find(':');
    if (first == std::string::npos || first == 0) return false;
    const std::size_t second = rest.find(':', first + 1);
    if (second == std::string::npos) return false;
    from = rest.substr(0, first);
    payload = rest.substr(second + 1);
    return true;
}

bool IsNotice(const std::string& line, const char* token) {
    return line.rfind("SYSTEM:", 0) == 0 && line.find(token) != std::string::npos;
}

bool BannerHasProto2(const std::string& line) {
    std::size_t pos = line.find("PROTO=2");
    while (pos != std::string::npos) {
        const std::size_t end = pos + 7;
        if (end >= line.size() || line[end] < '0' || line[end] > '9') return true;
        pos = line.find("PROTO=2", end);
    }
    return false;
}

void Fatal(const std::string& message) {
    std::cerr << "\033[1;31m[!] " << message << "\033[0m" << std::endl;
}

void SendAdminText(SocketHandle sock, const std::string& text) {
    SendAdminLine(sock, "[MSG]:" + river::base64::EncodeString(text));
}

// Protocol v2 handshake (PROTOCOL_V2.md section 2). Returns true only after a
// verified AUTH_OK followed by ACCESO CONCEDIDO. The console never publishes
// an identity key (no KEY_SET): it cannot read or send E2E private messages.
bool AuthenticateV2(SocketHandle sock, const std::string& user, const std::string& pass) {
    std::string line;
    bool gotBanner = false;
    for (int i = 0; i < 10 && !gotBanner; ++i) {
        if (!ReadProtocolLine(sock, line)) break;
        if (IsNotice(line, "UPLINK ESTABLISHED")) gotBanner = true;
    }
    if (!gotBanner) {
        Fatal("ERROR: El servidor no envio el banner de enlace.");
        return false;
    }
    if (!BannerHasProto2(line)) {
        Fatal("ERROR: Servidor incompatible (se requiere protocolo 2).");
        return false;
    }
    if (user.empty() || user.find_first_of(":|") != std::string::npos || pass.empty()) {
        Fatal("ERROR: Identificador o clave invalidos.");
        return false;
    }

    const std::string hwid = MakeStableMachineId();
    const std::string clientNonce = river::scram::RandomNonceHex(16);
    if (clientNonce.empty()) {
        Fatal("ERROR: No se pudo generar el nonce de autenticacion.");
        return false;
    }
    SendAdminLine(sock, "[AUTH_START]:2:" + user + ":" + hwid + ":" + clientNonce);

    std::string expectedServerSig;
    bool verified = false;
    for (int i = 0; i < 20; ++i) {
        if (!ReadProtocolLine(sock, line)) {
            Fatal("ERROR: Conexion cerrada durante la autenticacion.");
            return false;
        }
        if (line == "PING") {
            SendAdminLine(sock, "PONG");
            continue;
        }
        if (line.rfind("AUTH_CHALLENGE2:", 0) == 0) {
            std::vector<std::string> parts;
            {
                std::stringstream ss(line);
                std::string part;
                while (std::getline(ss, part, ':')) parts.push_back(part);
            }
            if (parts.size() != 4 || !expectedServerSig.empty()) {
                Fatal("ERROR: Reto corrupto o incompatible.");
                return false;
            }
            const std::string& combined = parts[1];
            const std::string& saltHex = parts[2];
            int iterations = 0;
            try {
                iterations = std::stoi(parts[3]);
            } catch (...) {
                iterations = 0;
            }
            if (combined.size() != clientNonce.size() + 32 ||
                combined.compare(0, clientNonce.size(), clientNonce) != 0 ||
                !river::scram::IsHexString(combined, combined.size())) {
                Fatal("ERROR: Reto con nonce invalido.");
                return false;
            }
            const std::string authMessage =
                river::scram::BuildAuthMessage(user, hwid, clientNonce, combined, saltHex, iterations);
            std::string proof;
            if (authMessage.empty() ||
                !river::scram::ComputeClientProof(pass, saltHex, iterations, authMessage, proof, expectedServerSig)) {
                Fatal("ERROR: Derivacion de clave fallida.");
                return false;
            }
            SendAdminLine(sock, "[AUTH_PROOF]:" + user + ":" + hwid + ":" + combined + ":" +
                                    river::base64::EncodeString(proof));
            continue;
        }
        if (line.rfind("AUTH_OK:", 0) == 0) {
            std::string received;
            if (expectedServerSig.empty() ||
                !river::base64::DecodeToString(line.substr(8), received) ||
                !river::scram::VerifyServerSignature(expectedServerSig, received)) {
                Fatal("ERROR: Firma del servidor invalida: autenticacion mutua fallida.");
                return false;
            }
            verified = true;
            continue;
        }
        if (IsNotice(line, "ACCESO CONCEDIDO")) {
            if (!verified) {
                Fatal("ERROR: El servidor no verifico su identidad (falta AUTH_OK valido).");
                return false;
            }
            std::cout << "\033[1;32m[*] ACCESO CONCEDIDO.\033[0m" << std::endl;
            return true;
        }
        if (IsNotice(line, "FIRST LOGIN")) {
            Fatal("Primer acceso: cambia el identificador y la clave desde el cliente grafico antes de usar la consola.");
            return false;
        }
        if (IsNotice(line, "CREDENCIALES INCORRECTAS") || IsNotice(line, "ACCESO BLOQUEADO") ||
            IsNotice(line, "HWID NO RECONOCIDO") || IsNotice(line, "CLIENTE OBSOLETO")) {
            Fatal(line);
            return false;
        }
    }
    Fatal("ERROR: El servidor no completo la autenticacion.");
    return false;
}

void PrintPrompt() {
    std::cout << "\n\033[1;32mADMIN>\033[0m " << std::flush;
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

        if (line.rfind("HISTORY_BEGIN:", 0) == 0 || line == "HISTORY_END" ||
            line.rfind("KEY:", 0) == 0 || line.rfind("KEY_CHANGED:", 0) == 0 ||
            line.rfind("PMX:", 0) == 0 || line.rfind("AUTH_OK:", 0) == 0) {
            continue;
        }

        std::cout << "\r\033[K"; // Clear current line
        std::string from;
        std::string payload;
        if ((line.rfind("MSG:", 0) == 0 && SplitSenderTsPayload(line.substr(4), from, payload)) ||
            (line.rfind("HIST:", 0) == 0 && SplitSenderTsPayload(line.substr(5), from, payload))) {
            std::cout << "\033[1;36m[" << from << "]:\033[0m " << DecodeTextB64(payload);
            PrintPrompt();
        } else if (line.rfind("PM2:", 0) == 0 && SplitSenderTsPayload(line.substr(4), from, payload)) {
            // End-to-end encrypted for the GUI client's identity key: unreadable here.
            std::cout << "\033[1;33m[PM cifrado de " << from << "]\033[0m";
            PrintPrompt();
        } else if (line.rfind("ATTACH2:", 0) == 0) {
            std::vector<std::string> parts;
            {
                std::stringstream ss(line.substr(8));
                std::string part;
                while (std::getline(ss, part, ':')) parts.push_back(part);
            }
            std::string name;
            if (parts.size() >= 4) name = DecodeTextB64(parts[3]);
            std::cout << "\033[1;36m[" << (parts.empty() ? std::string("?") : parts[0]) << "]:\033[0m [adjunto] " << name;
            PrintPrompt();
        } else if (line.find("SYSTEM") != std::string::npos) {
            std::cout << "\033[1;31m" << line << "\033[0m";
            PrintPrompt();
        } else {
            std::cout << line;
            PrintPrompt();
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
        std::cerr << "\033[1;31m[!] FATAL: Falta la variable de entorno THE_RIVER_ONION.\033[0m" << std::endl;
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

    const bool authenticated = AuthenticateV2(adminSocket, adminUser, adminPass);
    for (char& c : adminPass) c = '\0';
    adminPass.clear();
    if (!authenticated) {
        CloseSocketHandle(adminSocket);
        return 1;
    }

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
        if (!parts.empty() && (parts[0] == "/msg" || parts[0] == "/pm" || parts[0] == "/w" || parts[0] == "/r")) {
            std::cout << "\033[1;33mLos mensajes privados van cifrados de extremo a extremo y requieren el cliente "
                         "grafico (la consola no tiene clave de identidad). Mensaje no enviado.\033[0m"
                         "\n\033[1;32mADMIN>\033[0m ";
            continue;
        }
        if (!parts.empty() && parts[0] == "/help") {
            std::cout << "\033[1;33mConsola: /clear /exit; /passwd <usuario> pide la clave sin eco. "
                         "Los PM entrantes se muestran como [PM cifrado de <usuario>] y /msg no esta disponible: "
                         "usa el cliente grafico para mensajes privados.\033[0m\n";
        }
        if (parts.size() == 2 && parts[0] == "/passwd") {
            std::cout << "\033[1;33mNUEVA CLAVE PARA " << parts[1] << ": \033[0m";
            const std::string newPass = ReadSecretLine();
            input = "/passwd " + parts[1] + " " + newPass;
        }

        SendAdminText(adminSocket, input);
        for (char& c : input) c = '\0';
        std::cout << "\033[1;32mADMIN>\033[0m ";
    }

    std::cout << "\033[1;32m[*] CERRANDO SESION SEGURA...\033[0m\n";
#ifdef _WIN32
    shutdown(adminSocket, SD_BOTH);
#else
    shutdown(adminSocket, SHUT_RDWR);
#endif
    CloseSocketHandle(adminSocket);
    if (receiver.joinable()) receiver.join();
    return 0;
}
