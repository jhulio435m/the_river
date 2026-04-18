#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <deque>
#include <sstream>
#include <cstring>
#include <cmath>
#include <ctime>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#define SOCKET int
#define INVALID_SOCKET -1
#endif

#include <limits.h>
#include "imgui_src/imgui.h"
#include "imgui_src/backends/imgui_impl_glfw.h"
#include "imgui_src/backends/imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>
#include "include/aes.h"

// --- CONFIGURACIÓN ---
std::string ONION_ADDR = "3k4kzzkhiy6oyitin3g3wuy7hs6sf7tmcqdipe2vwaqxfyiggedltiid.onion";
std::string PROXY_IP = "127.0.0.1";
int PROXY_PORT = 9050;
const std::string AES_KEY = "RIVER_SECURE_KEY_2026_X";
const std::string AES_IV = "IV_VECTOR_091234";

// --- ESTADO ---
bool g_LoadingComplete = false;
bool g_Authenticated = false;
bool g_MustChange = false;
struct LogEntry { std::string time; std::string user; std::string text; bool isSystem; };
std::deque<LogEntry> g_ChatLogs;
std::vector<std::string> g_ActiveUsers;
std::mutex g_ChatMutex;
SOCKET g_ClientSocket = INVALID_SOCKET;
char g_InputBuf[256] = "";
char g_UserBuf[32] = "admin1";
char g_PassBuf[32] = "176132";
char g_NewUser[32] = "";
char g_NewPass[32] = "";

std::string GetTimestamp() {
    time_t now = time(0);
    struct tm tstruct;
    char buf[10];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%H:%M", &tstruct);
    return buf;
}

void AddLog(std::string msg) {
    std::lock_guard<std::mutex> lock(g_ChatMutex);
    std::string ts = GetTimestamp();
    
    // Limpieza de caracteres de control
    msg.erase(std::remove(msg.begin(), msg.end(), '\r'), msg.end());
    msg.erase(std::remove(msg.begin(), msg.end(), '\n'), msg.end());

    if (msg.find("[USERS]:") == 0) {
        g_ActiveUsers.clear();
        std::string rawList = msg.substr(8);
        std::stringstream ss(rawList);
        std::string name;
        while (std::getline(ss, name, ',')) {
            if(!name.empty()) g_ActiveUsers.push_back(name);
        }
    } else if (msg.find(":") != std::string::npos && msg.find("SYSTEM") == std::string::npos) {
        size_t sep = msg.find(":");
        std::string user = msg.substr(0, sep);
        std::string cipher = msg.substr(sep + 1);
        std::string decrypted = AESHelper::Decrypt(cipher, AES_KEY, AES_IV);
        g_ChatLogs.push_back({ts, user, decrypted, false});
    } else {
        g_ChatLogs.push_back({ts, "SYSTEM", msg, true});
    }
    if (g_ChatLogs.size() > 100) g_ChatLogs.pop_front();
}

std::string GetHWID() {
    char hostname[HOST_NAME_MAX] = "linux-node";
    gethostname(hostname, HOST_NAME_MAX);
    return AESHelper::Encrypt(std::string(hostname), "HWID_SALT", "0123456789ABCDEF").substr(0, 12);
}

bool ConnectTor() {
    g_ClientSocket = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv; tv.tv_sec = 10; tv.tv_usec = 0;
    setsockopt(g_ClientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(struct timeval));

    sockaddr_in addr; addr.sin_family = AF_INET; addr.sin_port = htons(PROXY_PORT);
    inet_pton(AF_INET, PROXY_IP.c_str(), &addr.sin_addr);
    if (connect(g_ClientSocket, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(g_ClientSocket);
        g_ClientSocket = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in l; l.sin_family = AF_INET; l.sin_port = htons(8888); inet_pton(AF_INET, "127.0.0.1", &l.sin_addr);
        if (connect(g_ClientSocket, (struct sockaddr*)&l, sizeof(l)) != 0) return false;
        std::cout << "[DEBUG] Conectado Localmente." << std::endl;
        return true;
    }
    char hello[] = {0x05, 0x01, 0x00}; send(g_ClientSocket, hello, 3, 0);
    char res[2]; recv(g_ClientSocket, res, 2, 0);
    std::vector<char> req = {0x05, 0x01, 0x00, 0x03};
    req.push_back((char)ONION_ADDR.length());
    for(char c : ONION_ADDR) req.push_back(c);
    req.push_back(0x00); req.push_back(0x50); 
    send(g_ClientSocket, req.data(), req.size(), 0);
    char reply[10]; recv(g_ClientSocket, reply, 10, 0);
    return reply[1] == 0x00;
}

void ReceiveThread() {
    char buf[16384];
    std::string accumulated;
    while (true) {
        int b = recv(g_ClientSocket, buf, 16383, 0);
        if (b == 0) break;
        if (b < 0) {
            #ifdef _WIN32
            if (WSAGetLastError() == WSAETIMEDOUT) continue;
            #else
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            #endif
            break;
        }
        buf[b] = '\0';
        accumulated += buf;
        size_t pos;
        while ((pos = accumulated.find('\n')) != std::string::npos) {
            std::string line = accumulated.substr(0, pos);
            accumulated.erase(0, pos + 1);
            if (line.find("FIRST LOGIN") != std::string::npos) g_MustChange = true;
            else if (line.find("ACCESO CONCEDIDO") != std::string::npos) { 
                g_Authenticated = true; g_MustChange = false; 
            }
            else AddLog(line);
        }
    }
    g_Authenticated = false; g_LoadingComplete = false;
}

void MainLoop() {
    while (true) {
        if (ConnectTor()) { g_LoadingComplete = true; ReceiveThread(); }
        else { g_LoadingComplete = false; std::this_thread::sleep_for(std::chrono::seconds(5)); }
    }
}

void ApplyEliteStyle() {
    ImGuiStyle& style = ImGui::GetStyle();
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.01f, 0.01f, 0.01f, 1.00f);
    style.Colors[ImGuiCol_Border] = ImVec4(0.00f, 1.00f, 0.50f, 0.30f);
    style.Colors[ImGuiCol_Text] = ImVec4(0.00f, 0.90f, 0.20f, 1.00f);
    style.Colors[ImGuiCol_Button] = ImVec4(0.00f, 0.25f, 0.00f, 1.00f);
    style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.00f, 0.50f, 0.00f, 1.00f);
    style.Colors[ImGuiCol_FrameBg] = ImVec4(0.02f, 0.02f, 0.02f, 1.00f);
    style.WindowRounding = 4.0f; style.FrameRounding = 2.0f;
}

int main() {
    if (!glfwInit()) return 1;
    GLFWwindow* win = glfwCreateWindow(900, 600, "THE RIVER | ELITE SUITE", NULL, NULL);
    glfwMakeContextCurrent(win); ImGui::CreateContext(); ApplyEliteStyle();
    ImGui_ImplGlfw_InitForOpenGL(win, true); ImGui_ImplOpenGL3_Init("#version 130");
    std::thread(MainLoop).detach();

    while (!glfwWindowShouldClose(win)) {
        glfwPollEvents(); ImGui_ImplOpenGL3_NewFrame(); ImGui_ImplGlfw_NewFrame(); ImGui::NewFrame();
        ImGui::SetNextWindowPos(ImVec2(0,0)); ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
        ImGui::Begin("MAINFRAME", NULL, ImGuiWindowFlags_NoTitleBar|ImGuiWindowFlags_NoResize|ImGuiWindowFlags_NoMove);

        if (!g_LoadingComplete) {
            float time = (float)glfwGetTime();
            ImGui::SetCursorPos(ImVec2(ImGui::GetIO().DisplaySize.x * 0.5f - 100, ImGui::GetIO().DisplaySize.y * 0.5f));
            ImGui::Text("CONNECTING TO TOR NETWORK...");
            ImGui::ProgressBar((sin(time * 5.0f) + 1.0f) * 0.5f, ImVec2(200, 4), "");
        } else if (!g_Authenticated) {
            ImVec2 winSize = ImGui::GetIO().DisplaySize;
            ImGui::SetCursorPos(ImVec2(winSize.x * 0.5f - 150, winSize.y * 0.5f - 100));
            ImGui::BeginChild("Auth", ImVec2(300, 200), true);
            ImGui::Separator(); ImGui::Text(" SECURE ACCESS REQUIRED"); ImGui::Separator(); ImGui::Spacing();
            if (g_MustChange) {
                ImGui::Text("NEW ID:"); ImGui::InputText("##NID", g_NewUser, 32);
                ImGui::Text("NEW KEY:"); ImGui::InputText("##NPW", g_NewPass, 32, ImGuiInputTextFlags_Password);
                if (ImGui::Button("UPDATE & SYNC", ImVec2(280, 40))) {
                    std::string c = "[CHANGE]:" + std::string(g_NewUser) + ":" + std::string(g_NewPass) + "\n";
                    send(g_ClientSocket, c.c_str(), (int)c.length(), 0);
                }
            } else {
                ImGui::Text("IDENT:"); ImGui::InputText("##ID", g_UserBuf, 32);
                ImGui::Text("KEY:"); ImGui::InputText("##PW", g_PassBuf, 32, ImGuiInputTextFlags_Password);
                if (ImGui::Button("ESTABLISH UPLINK", ImVec2(280, 40))) {
                    std::string cmd = "[LOGIN]:" + std::string(g_UserBuf) + ":" + std::string(g_PassBuf) + ":" + GetHWID() + "\n";
                    send(g_ClientSocket, cmd.c_str(), (int)cmd.length(), 0);
                }
            }
            ImGui::EndChild();
        } else {
            // SIDEBAR
            ImGui::BeginChild("Nodes", ImVec2(180, -1), true);
            ImGui::TextColored(ImVec4(0,1,0.5f,1), " ACTIVE NODES (%d)", (int)g_ActiveUsers.size()); 
            ImGui::Separator();
            for (auto& u : g_ActiveUsers) {
                if (u.find("admin") != std::string::npos) ImGui::TextColored(ImVec4(1,0,0,1), "[!] %s", u.c_str());
                else ImGui::BulletText("%s", u.c_str());
            }
            ImGui::EndChild();
            ImGui::SameLine();

            // CHAT
            ImGui::BeginGroup();
            ImGui::BeginChild("Feed", ImVec2(-1, -60), true);
            {
                std::lock_guard<std::mutex> lock(g_ChatMutex);
                for (auto& l : g_ChatLogs) {
                    ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.4f, 1.0f), "[%s]", l.time.c_str()); ImGui::SameLine();
                    if (l.isSystem) {
                        ImGui::TextColored(ImVec4(1,1,0,1), "SYSTEM> %s", l.text.c_str());
                    } else {
                        ImGui::TextColored(ImVec4(0,1,0,1), "%s>", l.user.c_str()); ImGui::SameLine();
                        ImGui::TextWrapped("%s", l.text.c_str());
                    }
                }
            }
            ImGui::SetScrollHereY(1.0f);
            ImGui::EndChild();

            ImGui::PushItemWidth(-1);
            if (ImGui::InputText("##CMD", g_InputBuf, 256, ImGuiInputTextFlags_EnterReturnsTrue)) {
                std::string input(g_InputBuf);
                if (input == "/clear") {
                    std::lock_guard<std::mutex> lock(g_ChatMutex);
                    g_ChatLogs.clear();
                } else if (input.length() > 0) {
                    std::string enc = AESHelper::Encrypt(input, AES_KEY, AES_IV);
                    std::string pay = std::string(g_UserBuf) + ":" + enc + "\n";
                    send(g_ClientSocket, pay.c_str(), (int)pay.length(), 0);
                    // ECO LOCAL (Para ver tu mensaje al instante)
                    {
                        std::lock_guard<std::mutex> lock(g_ChatMutex);
                        g_ChatLogs.push_back({GetTimestamp(), std::string(g_UserBuf), input, false});
                    }
                }
                memset(g_InputBuf, 0, 256);
                ImGui::SetKeyboardFocusHere(-1);
            }
            ImGui::PopItemWidth(); ImGui::EndGroup();
        }
        ImGui::End(); ImGui::Render(); glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData()); glfwSwapBuffers(win);
    }
    return 0;
}
