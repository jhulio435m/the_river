#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <map>
#include <sstream>
#include <fstream>
#include <cstring>
#include <sqlite3.h>
#include <iomanip>
#include <algorithm>
#include <ctime>
#include "include/aes.h"

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define close closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
#endif

// --- CONFIGURACIÓN ---
const int PORT = 8888;
const std::string AES_KEY = "RIVER_SECURE_KEY_2026_X";
const std::string AES_IV = "IV_VECTOR_091234";
const std::string LOG_FILE = "Orchestrator/chat_history.log";

// --- SHA-256 STANDALONE ---
#define SHA2_SHFR(x, n)    (x >> n)
#define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA2_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_F1(x) (SHA2_ROTR(x,  2) ^ SHA2_ROTR(x, 13) ^ SHA2_ROTR(x, 22))
#define SHA256_F2(x) (SHA2_ROTR(x,  6) ^ SHA2_ROTR(x, 11) ^ SHA2_ROTR(x, 25))
#define SHA256_F3(x) (SHA2_ROTR(x,  7) ^ SHA2_ROTR(x, 18) ^ SHA2_SHFR(x,  3))
#define SHA256_F4(x) (SHA2_ROTR(x, 17) ^ SHA2_ROTR(x, 19) ^ SHA2_SHFR(x, 10))

const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

std::string HashPassword(const std::string& input) {
    uint32_t h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    std::vector<uint8_t> msg(input.begin(), input.end());
    uint64_t n = msg.size() * 8;
    msg.push_back(0x80);
    while ((msg.size() * 8) % 512 != 448) msg.push_back(0x00);
    for (int i = 7; i >= 0; i--) msg.push_back((n >> (i * 8)) & 0xFF);
    for (size_t i = 0; i < msg.size() / 64; i++) {
        uint32_t w[64];
        for (int j = 0; j < 16; j++) w[j] = (msg[i * 64 + j * 4] << 24) | (msg[i * 64 + j * 4 + 1] << 16) | (msg[i * 64 + j * 4 + 2] << 8) | (msg[i * 64 + j * 4 + 3]);
        for (int j = 16; j < 64; j++) w[j] = SHA256_F4(w[j - 2]) + w[j - 7] + SHA256_F3(w[j - 15]) + w[j - 16];
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], m = h[7];
        for (int j = 0; j < 64; j++) {
            uint32_t t1 = m + SHA256_F2(e) + SHA2_CH(e, f, g) + sha256_k[j] + w[j];
            uint32_t t2 = SHA256_F1(a) + SHA2_MAJ(a, b, c);
            m = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += m;
    }
    std::stringstream ss;
    for (int i = 0; i < 8; i++) ss << std::hex << std::setw(8) << std::setfill('0') << h[i];
    return ss.str();
}

struct Client { int socket; std::string nick; bool auth; };
std::map<int, Client> g_Clients;
std::mutex g_ClientsMutex;
std::mutex g_LogMutex;
sqlite3* g_DB;

void LogToFile(const std::string& user, const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_LogMutex);
    std::ofstream file(LOG_FILE, std::ios::app);
    if (file.is_open()) {
        std::time_t now = std::time(nullptr);
        char time_str[100];
        std::strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
        file << time_str << "|" << user << ":" << msg << std::endl;
    }
}

void Broadcast(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_ClientsMutex);
    std::string fullMsg = msg + "\n";
    for (auto const& [sock, client] : g_Clients) {
        if (client.auth) send(sock, fullMsg.c_str(), fullMsg.length(), 0);
    }
}

void BroadcastUsers() {
    std::lock_guard<std::mutex> lock(g_ClientsMutex);
    std::string list = "[USERS]:";
    for (auto const& [sock, client] : g_Clients) {
        if (client.auth) list += client.nick + ",";
    }
    list += "\n";
    for (auto const& [sock, client] : g_Clients) {
        if (client.auth) send(sock, list.c_str(), list.length(), 0);
    }
}

void InitDatabase() {
    sqlite3_open("Orchestrator/secure_river.db", &g_DB);
    sqlite3_exec(g_DB, "CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT, first_login INTEGER DEFAULT 1, hwid TEXT);", 0, 0, 0);
    std::string hashDef = HashPassword("river123");
    for(int i=1; i<=4; i++) {
        std::string insert = "INSERT OR IGNORE INTO users (username, password_hash, first_login) VALUES ('user" + std::to_string(i) + "', '" + hashDef + "', 1);";
        sqlite3_exec(g_DB, insert.c_str(), 0, 0, 0);
    }
    std::string hashAdmin = HashPassword("176132");
    sqlite3_exec(g_DB, ("INSERT OR IGNORE INTO users (username, password_hash, first_login) VALUES ('admin1', '" + hashAdmin + "', 0);").c_str(), 0, 0, 0);
    sqlite3_exec(g_DB, ("INSERT OR IGNORE INTO users (username, password_hash, first_login) VALUES ('admin2', '" + hashAdmin + "', 0);").c_str(), 0, 0, 0);
}

int GetLoginState(const std::string& user, const std::string& pass, std::string& currentHwid) {
    std::string hash = HashPassword(pass);
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(g_DB, "SELECT first_login, hwid FROM users WHERE username = ? AND password_hash = ?;", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, user.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hash.c_str(), -1, SQLITE_STATIC);
    int result = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int first_login = sqlite3_column_int(stmt, 0);
        const char* savedHwid = (const char*)sqlite3_column_text(stmt, 1);
        if (!savedHwid) {
            sqlite3_stmt* up;
            sqlite3_prepare_v2(g_DB, "UPDATE users SET hwid = ? WHERE username = ?;", -1, &up, 0);
            sqlite3_bind_text(up, 1, currentHwid.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(up, 2, user.c_str(), -1, SQLITE_STATIC);
            sqlite3_step(up); sqlite3_finalize(up);
            result = first_login;
        } else if (currentHwid == std::string(savedHwid)) result = first_login;
        else result = -2;
    }
    sqlite3_finalize(stmt); return result;
}

bool UpdateUser(const std::string& oldUser, const std::string& newUser, const std::string& newPass) {
    std::string hash = HashPassword(newPass);
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(g_DB, "UPDATE users SET username = ?, password_hash = ?, first_login = 0 WHERE username = ?;", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, newUser.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, oldUser.c_str(), -1, SQLITE_STATIC);
    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt); return ok;
}

void HandleClient(int clientSocket) {
    char buffer[65536]; std::string accumulated;
    std::string currentNick = ""; bool authed = false;
    send(clientSocket, "SYSTEM: UPLINK ESTABLISHED.\n", 28, 0);
    while (true) {
        int b = recv(clientSocket, buffer, 65535, 0);
        if (b <= 0) break;
        buffer[b] = '\0'; accumulated += buffer;
        size_t pos;
        while ((pos = accumulated.find('\n')) != std::string::npos) {
            std::string raw = accumulated.substr(0, pos); accumulated.erase(0, pos + 1);
            if (raw.find("[LOGIN]:") == 0) {
                std::stringstream ss(raw.substr(8)); std::string u, p, h;
                std::getline(ss, u, ':'); std::getline(ss, p, ':'); std::getline(ss, h, ':');
                int state = GetLoginState(u, p, h);
                if (state == 1) { send(clientSocket, "SYSTEM: FIRST LOGIN. CHANGE REQUIRED.\n", 38, 0); currentNick = u; }
                else if (state == 0) {
                    send(clientSocket, "SYSTEM: ACCESO CONCEDIDO.\n", 26, 0);
                    currentNick = u; authed = true;
                    { std::lock_guard<std::mutex> lock(g_ClientsMutex); g_Clients[clientSocket] = {clientSocket, u, true}; }
                    Broadcast("SYSTEM: [+] NODE " + u + " UPLINKED.");
                    BroadcastUsers();
                } else send(clientSocket, "SYSTEM: CREDENCIALES INCORRECTAS.\n", 34, 0);
            } else if (raw.find("[CHANGE]:") == 0 && !currentNick.empty()) {
                std::stringstream ss(raw.substr(9)); std::string nu, np;
                std::getline(ss, nu, ':'); std::getline(ss, np, ':');
                if (UpdateUser(currentNick, nu, np)) send(clientSocket, "SYSTEM: UPDATED. RECONNECT NOW.\n", 32, 0);
            } else if (authed) {
                std::string payload = raw;
                if (raw.find(":") != std::string::npos) payload = raw.substr(raw.find(":") + 1);
                LogToFile(currentNick, payload);
                Broadcast(currentNick + ":" + payload);
            }
        }
    }
    { std::lock_guard<std::mutex> lock(g_ClientsMutex); g_Clients.erase(clientSocket); }
    if (!currentNick.empty() && authed) {
        Broadcast("SYSTEM: [-] NODE " + currentNick + " DISCONNECTED.");
        BroadcastUsers();
    }
    close(clientSocket);
}

int main() {
#ifdef _WIN32
    WSADATA wsaData; WSAStartup(MAKEWORD(2,2), &wsaData);
#endif
    InitDatabase();
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr; addr.sin_family = AF_INET; addr.sin_addr.s_addr = INADDR_ANY; addr.sin_port = htons(PORT);
    int opt = 1; setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    bind(serverSocket, (struct sockaddr*)&addr, sizeof(addr)); listen(serverSocket, 10);
    std::cout << ">>> THE RIVER SECURE SERVER ONLINE <<<" << std::endl;
    while(true) {
        int client = accept(serverSocket, 0, 0);
        std::thread(HandleClient, client).detach();
    }
    return 0;
}
