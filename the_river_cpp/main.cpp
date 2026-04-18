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
#include <atomic>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define closesocket close
#endif

#include <limits.h>
#include "imgui_src/imgui.h"
#include "imgui_src/backends/imgui_impl_glfw.h"
#include "imgui_src/backends/imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>
#include "include/aes.h"

// --- CONFIGURACION ---
std::string ONION_ADDR = "3k4kzzkhiy6oyitin3g3wuy7hs6sf7tmcqdipe2vwaqxfyiggedltiid.onion";
std::string PROXY_IP   = "127.0.0.1";
int         PROXY_PORT = 9050;
const std::string AES_KEY = "RIVER_SECURE_KEY";   // 16 bytes exactos para AES-128
const std::string AES_IV  = "";                    // IV generado aleatoriamente en cada Encrypt

// --- ESTADO DE CONEXION ---
enum class ConnState { DISCONNECTED, CONNECTING, TOR_OK, AUTHENTICATED };
std::atomic<int> g_ConnStateRaw{0};
inline ConnState GetConnState() { return (ConnState)g_ConnStateRaw.load(); }
inline void      SetConnState(ConnState s) { g_ConnStateRaw.store((int)s); }

// --- GLOBALES ---
bool g_Authenticated  = false;
bool g_MustChange     = false;
bool g_AutoScroll     = true;
bool g_NewMessage     = false;
GLFWwindow* g_Win     = nullptr;

struct LogEntry { std::string time; std::string user; std::string text; bool isSystem; bool isPM; };
std::deque<LogEntry> g_ChatLogs;
std::mutex           g_ChatMutex;

std::vector<std::string> g_ActiveUsers;
std::mutex               g_UsersMutex;

// Socket protegido con mutex
std::mutex g_SocketMutex;
SOCKET     g_Sock = INVALID_SOCKET;

char g_InputBuf[512] = "";
char g_UserBuf[32]   = "";   // Sin credenciales por defecto
char g_PassBuf[32]   = "";
char g_NewUser[32]   = "";
char g_NewPass[32]   = "";

// --- HELPERS ---
std::string GetTimestamp() {
    time_t now = time(0);
    struct tm t = *localtime(&now);
    char buf[20];
    strftime(buf, sizeof(buf), "%H:%M", &t);
    return buf;
}

int SafeSend(const std::string& payload) {
    std::lock_guard<std::mutex> lk(g_SocketMutex);
    if (g_Sock == INVALID_SOCKET) return -1;
    return send(g_Sock, payload.c_str(), (int)payload.size(), 0);
}

void AddLog(const std::string& rawMsg, bool isPM = false) {
    std::lock_guard<std::mutex> lk(g_ChatMutex);
    std::string msg = rawMsg;
    msg.erase(std::remove(msg.begin(), msg.end(), '\r'), msg.end());
    msg.erase(std::remove(msg.begin(), msg.end(), '\n'), msg.end());
    std::string ts = GetTimestamp();

    if (msg.find("[USERS]:") == 0) {
        std::lock_guard<std::mutex> lu(g_UsersMutex);
        g_ActiveUsers.clear();
        std::stringstream ss(msg.substr(8));
        std::string name;
        while (std::getline(ss, name, ','))
            if (!name.empty()) g_ActiveUsers.push_back(name);
    } else if (!isPM && msg.find(":") != std::string::npos
               && msg.find("SYSTEM") == std::string::npos) {
        size_t sep = msg.find(":");
        std::string user = msg.substr(0, sep);
        std::string dec  = AESHelper::Decrypt(msg.substr(sep + 1), AES_KEY, AES_IV);
        bool isOwn = (user == std::string(g_UserBuf));
        g_ChatLogs.push_back({ts, user, dec, false, false});
        if (!isOwn) g_NewMessage = true;
    } else if (isPM && msg.find(":") != std::string::npos) {
        size_t sep = msg.find(":");
        std::string user = msg.substr(0, sep);
        std::string dec  = AESHelper::Decrypt(msg.substr(sep + 1), AES_KEY, AES_IV);
        g_ChatLogs.push_back({ts, user, dec, false, true});
        g_NewMessage = true;
    } else {
        g_ChatLogs.push_back({ts, "SYSTEM", msg, true, false});
    }
    if (g_ChatLogs.size() > 200) g_ChatLogs.pop_front();
}

std::string GetHWID() {
    char hostname[HOST_NAME_MAX] = "node";
    gethostname(hostname, HOST_NAME_MAX);
    return AESHelper::Encrypt(std::string(hostname), "HWID_SALT_KEY_16", AES_IV).substr(0, 12);
}

// --- CONEXION TOR ---
bool ConnectTor() {
    SetConnState(ConnState::CONNECTING);
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv{10, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(PROXY_PORT);
    inet_pton(AF_INET, PROXY_IP.c_str(), &addr.sin_addr);

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        // Fallback local
        closesocket(s);
        s = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in l{}; l.sin_family=AF_INET; l.sin_port=htons(8888);
        inet_pton(AF_INET,"127.0.0.1",&l.sin_addr);
        if (connect(s,(struct sockaddr*)&l,sizeof(l)) != 0) {
            closesocket(s); SetConnState(ConnState::DISCONNECTED); return false;
        }
        std::lock_guard<std::mutex> lk(g_SocketMutex); g_Sock = s;
        SetConnState(ConnState::TOR_OK); return true;
    }
    // SOCKS5 handshake
    char hello[]={0x05,0x01,0x00}; send(s,hello,3,0);
    char res[2]; recv(s,res,2,0);
    std::vector<char> req={0x05,0x01,0x00,0x03};
    req.push_back((char)ONION_ADDR.size());
    for(char c:ONION_ADDR) req.push_back(c);
    req.push_back(0x00); req.push_back(0x50);
    send(s,req.data(),(int)req.size(),0);
    char reply[10]; recv(s,reply,10,0);
    if (reply[1] != 0x00) { closesocket(s); SetConnState(ConnState::DISCONNECTED); return false; }
    std::lock_guard<std::mutex> lk(g_SocketMutex); g_Sock = s;
    SetConnState(ConnState::TOR_OK); return true;
}

// --- HILO DE RECEPCION ---
void ReceiveThread() {
    char buf[16384];
    std::string accum;
    while (true) {
        SOCKET sock;
        { std::lock_guard<std::mutex> lk(g_SocketMutex); sock = g_Sock; }
        int b = recv(sock, buf, 16383, 0);
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
        accum += buf;
        if (accum.size() > 1024*1024) accum.clear(); // anti-OOM
        size_t pos;
        while ((pos = accum.find('\n')) != std::string::npos) {
            std::string line = accum.substr(0, pos);
            accum.erase(0, pos + 1);
            if (line == "PING") {
                SafeSend("PONG\n");
            } else if (line.find("FIRST LOGIN") != std::string::npos) {
                g_MustChange = true;
            } else if (line.find("ACCESO CONCEDIDO") != std::string::npos) {
                g_Authenticated = true; g_MustChange = false;
                SetConnState(ConnState::AUTHENTICATED);
            } else if (line.find("[PM]:") == 0) {
                AddLog(line.substr(5), true);
            } else {
                AddLog(line);
            }
        }
    }
    g_Authenticated = false;
    SetConnState(ConnState::DISCONNECTED);
}

// --- LOOP PRINCIPAL DE RED ---
void MainLoop() {
    while (true) {
        // Cerrar socket anterior si existe (evitar leak)
        {
            std::lock_guard<std::mutex> lk(g_SocketMutex);
            if (g_Sock != INVALID_SOCKET) { closesocket(g_Sock); g_Sock = INVALID_SOCKET; }
        }
        if (ConnectTor()) {
            ReceiveThread();
        } else {
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
}

// --- ESTILO ---
void ApplyEliteStyle() {
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding = 6.0f; s.FrameRounding = 4.0f; s.ScrollbarRounding = 4.0f;
    s.Colors[ImGuiCol_WindowBg]      = ImVec4(0.01f,0.01f,0.02f,1.00f);
    s.Colors[ImGuiCol_Border]        = ImVec4(0.00f,1.00f,0.50f,0.25f);
    s.Colors[ImGuiCol_Text]          = ImVec4(0.00f,0.90f,0.20f,1.00f);
    s.Colors[ImGuiCol_Button]        = ImVec4(0.00f,0.20f,0.00f,1.00f);
    s.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.00f,0.45f,0.00f,1.00f);
    s.Colors[ImGuiCol_ButtonActive]  = ImVec4(0.00f,0.60f,0.10f,1.00f);
    s.Colors[ImGuiCol_FrameBg]       = ImVec4(0.02f,0.04f,0.02f,1.00f);
    s.Colors[ImGuiCol_FrameBgHovered]= ImVec4(0.04f,0.10f,0.04f,1.00f);
    s.Colors[ImGuiCol_Header]        = ImVec4(0.00f,0.30f,0.00f,1.00f);
    s.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.00f,0.45f,0.00f,1.00f);
    s.Colors[ImGuiCol_ScrollbarBg]   = ImVec4(0.01f,0.01f,0.01f,1.00f);
    s.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.00f,0.40f,0.00f,1.00f);
    s.Colors[ImGuiCol_TitleBg]       = ImVec4(0.00f,0.10f,0.00f,1.00f);
    s.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.00f,0.20f,0.05f,1.00f);
    s.Colors[ImGuiCol_Separator]     = ImVec4(0.00f,0.50f,0.20f,0.50f);
    s.Colors[ImGuiCol_ChildBg]       = ImVec4(0.01f,0.02f,0.01f,1.00f);
}

// --- PROCESAR COMANDOS LOCALES ---
void ProcessCommand(const std::string& input) {
    if (input == "/clear") {
        std::lock_guard<std::mutex> lk(g_ChatMutex);
        g_ChatLogs.clear();
    } else if (input == "/help") {
        std::lock_guard<std::mutex> lk(g_ChatMutex);
        g_ChatLogs.push_back({GetTimestamp(),"SYSTEM","Comandos: /clear /help /users /ping /pm <user> <msg>",true,false});
    } else if (input == "/users") {
        std::string list = "Nodos activos: ";
        { std::lock_guard<std::mutex> lu(g_UsersMutex);
          for (auto& u : g_ActiveUsers) list += u + " "; }
        std::lock_guard<std::mutex> lk(g_ChatMutex);
        g_ChatLogs.push_back({GetTimestamp(),"SYSTEM",list,true,false});
    } else if (input == "/ping") {
        SafeSend("PING\n");
        std::lock_guard<std::mutex> lk(g_ChatMutex);
        g_ChatLogs.push_back({GetTimestamp(),"SYSTEM","PING enviado al servidor.",true,false});
    } else if (input.substr(0,3) == "/pm") {
        // /pm <user> <mensaje>
        std::string rest = input.size() > 4 ? input.substr(4) : "";
        size_t sp = rest.find(' ');
        if (sp == std::string::npos) {
            std::lock_guard<std::mutex> lk(g_ChatMutex);
            g_ChatLogs.push_back({GetTimestamp(),"SYSTEM","Uso: /pm <user> <mensaje>",true,false});
        } else {
            std::string target = rest.substr(0, sp);
            std::string msg    = rest.substr(sp + 1);
            std::string enc    = AESHelper::Encrypt(msg, AES_KEY, AES_IV);
            SafeSend("[PM]:" + target + ":" + std::string(g_UserBuf) + ":" + enc + "\n");
            std::lock_guard<std::mutex> lk(g_ChatMutex);
            g_ChatLogs.push_back({GetTimestamp(),std::string(g_UserBuf),"[PM→"+target+"] "+msg,false,true});
        }
    } else if (!input.empty()) {
        std::string enc = AESHelper::Encrypt(input, AES_KEY, AES_IV);
        SafeSend(std::string(g_UserBuf) + ":" + enc + "\n");
        std::lock_guard<std::mutex> lk(g_ChatMutex);
        g_ChatLogs.push_back({GetTimestamp(), std::string(g_UserBuf), input, false, false});
    }
}

// ============================================================
int main() {
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
    if (!glfwInit()) return 1;
    g_Win = glfwCreateWindow(960, 620, "THE RIVER | ELITE SUITE", NULL, NULL);
    glfwMakeContextCurrent(g_Win);
    ImGui::CreateContext();
    ImGui::GetIO().IniFilename = nullptr;
    ApplyEliteStyle();
    ImGui_ImplGlfw_InitForOpenGL(g_Win, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    std::thread(MainLoop).detach();

    double lastTitleUpdate = 0.0;

    while (!glfwWindowShouldClose(g_Win)) {
        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // Notificacion de ventana
        if (g_NewMessage) {
            glfwRequestWindowAttention(g_Win);
            g_NewMessage = false;
        }

        // Actualizar titulo cada segundo
        double now = glfwGetTime();
        if (now - lastTitleUpdate > 1.0) {
            lastTitleUpdate = now;
            const char* stateStr = "";
            switch (GetConnState()) {
                case ConnState::DISCONNECTED:  stateStr = "OFFLINE";        break;
                case ConnState::CONNECTING:    stateStr = "CONNECTING...";  break;
                case ConnState::TOR_OK:        stateStr = "TOR OK";         break;
                case ConnState::AUTHENTICATED: stateStr = "SECURE";         break;
            }
            int nUsers = 0;
            { std::lock_guard<std::mutex> lu(g_UsersMutex); nUsers = (int)g_ActiveUsers.size(); }
            char title[256];
            snprintf(title, sizeof(title),
                "THE RIVER | ELITE SUITE  [%s]  [Nodes: %d]  [%s]",
                stateStr, nUsers, GetTimestamp().c_str());
            glfwSetWindowTitle(g_Win, title);
        }

        ImGui::SetNextWindowPos(ImVec2(0,0));
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
        ImGui::Begin("##MAIN", NULL,
            ImGuiWindowFlags_NoTitleBar|ImGuiWindowFlags_NoResize|
            ImGuiWindowFlags_NoMove|ImGuiWindowFlags_NoBringToFrontOnFocus);

        ConnState cs = GetConnState();

        // ---- PANTALLA DE CARGA / ESTADO ----
        if (cs != ConnState::AUTHENTICATED && !g_Authenticated) {
            ImVec2 sz = ImGui::GetIO().DisplaySize;
            float cx = sz.x * 0.5f, cy = sz.y * 0.5f;

            if (cs == ConnState::DISCONNECTED || cs == ConnState::CONNECTING) {
                // Indicador animado
                float t = (float)glfwGetTime();
                ImVec4 col = (cs == ConnState::DISCONNECTED)
                    ? ImVec4(0.8f,0.1f,0.0f,1.0f) : ImVec4(0.0f,0.8f,0.3f,1.0f);
                const char* msg = (cs == ConnState::DISCONNECTED)
                    ? "OFFLINE — REINTENTANDO..." : "CONECTANDO A LA RED TOR...";
                ImVec2 tsz = ImGui::CalcTextSize(msg);
                ImGui::SetCursorPos(ImVec2(cx - tsz.x*0.5f, cy - 20));
                ImGui::TextColored(col, "%s", msg);
                ImGui::SetCursorPos(ImVec2(cx - 120, cy + 5));
                ImGui::ProgressBar((sinf(t*4.0f)+1.0f)*0.5f, ImVec2(240,6),"");
            } else if (cs == ConnState::TOR_OK && !g_Authenticated) {
                // LOGIN
                ImGui::SetCursorPos(ImVec2(cx - 155, cy - 110));
                ImGui::BeginChild("##Auth", ImVec2(310, 220), true);
                ImGui::Spacing();
                ImGui::TextColored(ImVec4(0,1,0.5f,1)," ╔══ SECURE ACCESS ══╗");
                ImGui::Separator(); ImGui::Spacing();
                if (g_MustChange) {
                    ImGui::Text("NUEVO ID:");  ImGui::InputText("##NID", g_NewUser, 32);
                    ImGui::Text("NUEVA KEY:"); ImGui::InputText("##NPW", g_NewPass, 32, ImGuiInputTextFlags_Password);
                    if (ImGui::Button("UPDATE & SYNC", ImVec2(290,40))) {
                        std::string c = "[CHANGE]:" + std::string(g_NewUser) + ":" + std::string(g_NewPass) + "\n";
                        SafeSend(c);
                    }
                } else {
                    ImGui::Text("IDENT:"); ImGui::InputText("##ID", g_UserBuf, 32);
                    ImGui::Text("KEY:");   ImGui::InputText("##PW", g_PassBuf, 32, ImGuiInputTextFlags_Password);
                    bool enter = ImGui::IsKeyPressed(ImGuiKey_Enter);
                    if (ImGui::Button("ESTABLISH UPLINK", ImVec2(290,40)) || enter) {
                        std::string cmd = "[LOGIN]:" + std::string(g_UserBuf) + ":" +
                                          std::string(g_PassBuf) + ":" + GetHWID() + "\n";
                        SafeSend(cmd);
                    }
                }
                ImGui::EndChild();
            }
        } else {
            // ---- VISTA PRINCIPAL AUTENTICADA ----

            // Sidebar de nodos
            ImGui::BeginChild("##Nodes", ImVec2(185,-1), true);
            {
                std::lock_guard<std::mutex> lu(g_UsersMutex);
                ImGui::TextColored(ImVec4(0,1,0.5f,1)," ACTIVE NODES (%d)",
                    (int)g_ActiveUsers.size());
                ImGui::Separator(); ImGui::Spacing();
                for (auto& u : g_ActiveUsers) {
                    if (u.find("admin") != std::string::npos)
                        ImGui::TextColored(ImVec4(1,0.3f,0.0f,1),"[!] %s", u.c_str());
                    else
                        ImGui::BulletText("%s", u.c_str());
                }
            }
            ImGui::EndChild();
            ImGui::SameLine();

            // Panel de chat
            ImGui::BeginGroup();
            float inputH  = 36.0f;
            float feedH   = ImGui::GetContentRegionAvail().y - inputH - 8.0f;
            ImGui::BeginChild("##Feed", ImVec2(-1, feedH), true);
            {
                std::lock_guard<std::mutex> lk(g_ChatMutex);
                for (auto& l : g_ChatLogs) {
                    ImGui::TextColored(ImVec4(0.35f,0.35f,0.35f,1),"[%s]", l.time.c_str());
                    ImGui::SameLine();
                    if (l.isSystem) {
                        ImGui::TextColored(ImVec4(1,0.85f,0,1),"SYSTEM> %s", l.text.c_str());
                    } else if (l.isPM) {
                        ImGui::TextColored(ImVec4(0.8f,0.3f,1.0f,1),"[PM] %s> ", l.user.c_str());
                        ImGui::SameLine();
                        ImGui::TextWrapped("%s", l.text.c_str());
                    } else {
                        bool own = (l.user == std::string(g_UserBuf));
                        ImVec4 ucol = own ? ImVec4(0.2f,0.8f,1.0f,1) : ImVec4(0,1,0,1);
                        ImGui::TextColored(ucol, "%s%s>", own ? ">> " : "", l.user.c_str());
                        ImGui::SameLine();
                        ImGui::TextWrapped("%s", l.text.c_str());
                    }
                }
            }
            // Auto-scroll inteligente
            float scrollY   = ImGui::GetScrollY();
            float scrollMax = ImGui::GetScrollMaxY();
            if (scrollMax > 0 && scrollY < scrollMax - 20.0f)
                g_AutoScroll = false;
            else
                g_AutoScroll = true;
            if (g_AutoScroll) ImGui::SetScrollHereY(1.0f);
            ImGui::EndChild();

            // Input
            ImGui::PushItemWidth(-1);
            ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.01f,0.06f,0.01f,1));
            bool send_msg = ImGui::InputText("##CMD", g_InputBuf, 512,
                ImGuiInputTextFlags_EnterReturnsTrue);
            ImGui::PopStyleColor();
            ImGui::PopItemWidth();
            if (send_msg) {
                ProcessCommand(std::string(g_InputBuf));
                memset(g_InputBuf, 0, sizeof(g_InputBuf));
                ImGui::SetKeyboardFocusHere(-1);
            }
            ImGui::EndGroup();
        }

        ImGui::End();
        ImGui::Render();
        glClearColor(0.01f,0.01f,0.02f,1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(g_Win);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(g_Win);
    glfwTerminate();
    return 0;
}
