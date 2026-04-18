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
#include <atomic>
#include "include/aes.h"

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define close closesocket
    typedef int socklen_t;
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

// --- CONFIGURACION ---
const int         PORT     = 8888;
const std::string AES_KEY  = "RIVER_SECURE_KEY";   // 16 bytes
const std::string AES_IV   = "";
const std::string LOG_FILE = "Orchestrator/chat_history.log";

// ============================================================
//  SHA-256 standalone
// ============================================================
#define SHA2_ROTR(x,n) ((x>>n)|(x<<(32-n)))
#define SHA2_CH(x,y,z)  ((x&y)^(~x&z))
#define SHA2_MAJ(x,y,z) ((x&y)^(x&z)^(y&z))
#define SHA256_F1(x) (SHA2_ROTR(x,2)^SHA2_ROTR(x,13)^SHA2_ROTR(x,22))
#define SHA256_F2(x) (SHA2_ROTR(x,6)^SHA2_ROTR(x,11)^SHA2_ROTR(x,25))
#define SHA256_F3(x) (SHA2_ROTR(x,7)^SHA2_ROTR(x,18)^(x>>3))
#define SHA256_F4(x) (SHA2_ROTR(x,17)^SHA2_ROTR(x,19)^(x>>10))

static const uint32_t sha256_k[64]={
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

std::string HashPassword(const std::string& input){
    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    std::vector<uint8_t> msg(input.begin(),input.end());
    uint64_t n=msg.size()*8;
    msg.push_back(0x80);
    while((msg.size()*8)%512!=448) msg.push_back(0x00);
    for(int i=7;i>=0;i--) msg.push_back((n>>(i*8))&0xFF);
    for(size_t i=0;i<msg.size()/64;i++){
        uint32_t w[64];
        for(int j=0;j<16;j++)
            w[j]=(msg[i*64+j*4]<<24)|(msg[i*64+j*4+1]<<16)|(msg[i*64+j*4+2]<<8)|msg[i*64+j*4+3];
        for(int j=16;j<64;j++)
            w[j]=SHA256_F4(w[j-2])+w[j-7]+SHA256_F3(w[j-15])+w[j-16];
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],m=h[7];
        for(int j=0;j<64;j++){
            uint32_t t1=m+SHA256_F2(e)+SHA2_CH(e,f,g)+sha256_k[j]+w[j];
            uint32_t t2=SHA256_F1(a)+SHA2_MAJ(a,b,c);
            m=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=m;
    }
    std::stringstream ss;
    for(int i=0;i<8;i++) ss<<std::hex<<std::setw(8)<<std::setfill('0')<<h[i];
    return ss.str();
}

// ============================================================
//  Estado global
// ============================================================
struct Client {
    int         socket;
    std::string nick;
    bool        auth;
    time_t      lastSeen;
};

std::map<int,Client> g_Clients;
std::mutex           g_ClientsMutex;
std::mutex           g_LogMutex;
sqlite3*             g_DB = nullptr;

// Rate limiting: intentos de login por nick
struct LoginAttempt { int count; time_t lockUntil; };
std::map<std::string,LoginAttempt> g_LoginAttempts;
std::mutex                         g_AttemptsMutex;

// ============================================================
//  Log cifrado en disco
// ============================================================
void LogToFile(const std::string& user, const std::string& msg){
    std::lock_guard<std::mutex> lk(g_LogMutex);
    std::ofstream f(LOG_FILE, std::ios::app);
    if(!f.is_open()) return;
    char ts[32]; std::time_t now=std::time(nullptr);
    std::strftime(ts,sizeof(ts),"%Y-%m-%d %H:%M:%S",std::localtime(&now));
    std::string entry = std::string(ts)+"|"+user+":"+msg;
    // Cifrar entrada antes de escribir
    std::string enc = AESHelper::Encrypt(entry, AES_KEY, AES_IV);
    f << enc << "\n";
}

// ============================================================
//  Broadcast / helpers de red
// ============================================================
void SendTo(int sock, const std::string& msg){
    std::string full = msg + "\n";
    send(sock, full.c_str(), (int)full.size(), 0);
}

void Broadcast(const std::string& msg){
    std::lock_guard<std::mutex> lk(g_ClientsMutex);
    for(auto& [sock,cl]:g_Clients)
        if(cl.auth) SendTo(sock,msg);
}

void BroadcastUsers(){
    std::lock_guard<std::mutex> lk(g_ClientsMutex);
    std::string list="[USERS]:";
    for(auto& [sock,cl]:g_Clients)
        if(cl.auth) list+=cl.nick+",";
    for(auto& [sock,cl]:g_Clients)
        if(cl.auth) SendTo(sock,list);
}

// Enviar mensaje privado a un nick especifico (mutex ya tomado por el llamador NO)
bool SendPM(const std::string& toNick, const std::string& fromNick, const std::string& encPayload){
    std::lock_guard<std::mutex> lk(g_ClientsMutex);
    for(auto& [sock,cl]:g_Clients){
        if(cl.auth && cl.nick==toNick){
            SendTo(sock, "[PM]:"+fromNick+":"+encPayload);
            return true;
        }
    }
    return false;
}

void KickUser(const std::string& nick){
    std::lock_guard<std::mutex> lk(g_ClientsMutex);
    for(auto& [sock,cl]:g_Clients){
        if(cl.nick==nick){
            SendTo(sock,"SYSTEM: KICKED BY ADMIN.");
            close(sock);
            break;
        }
    }
}

// ============================================================
//  Base de datos
// ============================================================
void InitDatabase(){
    sqlite3_open("Orchestrator/secure_river.db",&g_DB);
    sqlite3_exec(g_DB,
        "CREATE TABLE IF NOT EXISTS users "
        "(username TEXT PRIMARY KEY, password_hash TEXT, first_login INTEGER DEFAULT 1, hwid TEXT);",
        0,0,0);
    sqlite3_exec(g_DB,
        "CREATE TABLE IF NOT EXISTS banned_hwids "
        "(hwid TEXT PRIMARY KEY, reason TEXT, banned_at INTEGER);",
        0,0,0);
    // Usuarios por defecto
    std::string hashDef   = HashPassword("river123");
    std::string hashAdmin = HashPassword("176132");
    for(int i=1;i<=4;i++){
        std::string s="INSERT OR IGNORE INTO users (username,password_hash,first_login) VALUES ('user"
                      +std::to_string(i)+"','"+hashDef+"',1);";
        sqlite3_exec(g_DB,s.c_str(),0,0,0);
    }
    sqlite3_exec(g_DB,("INSERT OR IGNORE INTO users (username,password_hash,first_login) VALUES ('admin1','"+hashAdmin+"',0);").c_str(),0,0,0);
    sqlite3_exec(g_DB,("INSERT OR IGNORE INTO users (username,password_hash,first_login) VALUES ('admin2','"+hashAdmin+"',0);").c_str(),0,0,0);
    std::cout<<"[DB] Base de datos inicializada."<<std::endl;
}

bool IsHwidBanned(const std::string& hwid){
    sqlite3_stmt* st;
    sqlite3_prepare_v2(g_DB,"SELECT 1 FROM banned_hwids WHERE hwid=?;",-1,&st,0);
    sqlite3_bind_text(st,1,hwid.c_str(),-1,SQLITE_STATIC);
    bool banned=(sqlite3_step(st)==SQLITE_ROW);
    sqlite3_finalize(st);
    return banned;
}

void BanHwid(const std::string& hwid, const std::string& reason){
    sqlite3_stmt* st;
    sqlite3_prepare_v2(g_DB,
        "INSERT OR IGNORE INTO banned_hwids (hwid,reason,banned_at) VALUES (?,?,?);",-1,&st,0);
    sqlite3_bind_text(st,1,hwid.c_str(),-1,SQLITE_STATIC);
    sqlite3_bind_text(st,2,reason.c_str(),-1,SQLITE_STATIC);
    sqlite3_bind_int64(st,3,(sqlite3_int64)time(nullptr));
    sqlite3_step(st); sqlite3_finalize(st);
}

// Retorna: 0=ok, 1=primer_login, -1=creds_mal, -2=hwid_distinto, -3=bloqueado
int GetLoginState(const std::string& user, const std::string& pass, std::string& hwid){
    // Verificar ban de HWID
    if(IsHwidBanned(hwid)) return -3;
    // Rate limiting
    {
        std::lock_guard<std::mutex> la(g_AttemptsMutex);
        auto it=g_LoginAttempts.find(user);
        if(it!=g_LoginAttempts.end() && it->second.lockUntil>time(nullptr))
            return -3;
    }
    std::string hash=HashPassword(pass);
    sqlite3_stmt* st;
    sqlite3_prepare_v2(g_DB,
        "SELECT first_login,hwid FROM users WHERE username=? AND password_hash=?;",-1,&st,0);
    sqlite3_bind_text(st,1,user.c_str(),-1,SQLITE_STATIC);
    sqlite3_bind_text(st,2,hash.c_str(),-1,SQLITE_STATIC);
    int result=-1;
    if(sqlite3_step(st)==SQLITE_ROW){
        int fl=sqlite3_column_int(st,0);
        const char* savedHwid=(const char*)sqlite3_column_text(st,1);
        if(!savedHwid){
            sqlite3_stmt* up;
            sqlite3_prepare_v2(g_DB,"UPDATE users SET hwid=? WHERE username=?;",-1,&up,0);
            sqlite3_bind_text(up,1,hwid.c_str(),-1,SQLITE_STATIC);
            sqlite3_bind_text(up,2,user.c_str(),-1,SQLITE_STATIC);
            sqlite3_step(up); sqlite3_finalize(up);
            result=fl;
        } else if(hwid==std::string(savedHwid)){
            result=fl;
        } else {
            result=-2;
        }
    }
    sqlite3_finalize(st);
    // Actualizar contador de intentos
    {
        std::lock_guard<std::mutex> la(g_AttemptsMutex);
        if(result<0){
            auto& att=g_LoginAttempts[user];
            att.count++;
            if(att.count>=5){
                att.lockUntil=time(nullptr)+300; // 5 min
                att.count=0;
                std::cout<<"[SEC] Usuario '"<<user<<"' bloqueado por 5 min."<<std::endl;
            }
        } else {
            g_LoginAttempts.erase(user); // reset al login exitoso
        }
    }
    return result;
}

bool UpdateUser(const std::string& oldUser,const std::string& newUser,const std::string& newPass){
    std::string hash=HashPassword(newPass);
    sqlite3_stmt* st;
    sqlite3_prepare_v2(g_DB,
        "UPDATE users SET username=?,password_hash=?,first_login=0 WHERE username=?;",-1,&st,0);
    sqlite3_bind_text(st,1,newUser.c_str(),-1,SQLITE_STATIC);
    sqlite3_bind_text(st,2,hash.c_str(),-1,SQLITE_STATIC);
    sqlite3_bind_text(st,3,oldUser.c_str(),-1,SQLITE_STATIC);
    bool ok=(sqlite3_step(st)==SQLITE_DONE);
    sqlite3_finalize(st);
    return ok;
}

// ============================================================
//  Heartbeat thread
// ============================================================
void HeartbeatThread(){
    while(true){
        std::this_thread::sleep_for(std::chrono::seconds(30));
        std::vector<int> stale;
        {
            std::lock_guard<std::mutex> lk(g_ClientsMutex);
            time_t now=time(nullptr);
            for(auto& [sock,cl]:g_Clients){
                if(cl.auth){
                    if(now-cl.lastSeen>90){
                        stale.push_back(sock);
                    } else {
                        SendTo(sock,"PING");
                    }
                }
            }
        }
        for(int s:stale){
            std::cout<<"[HB] Cliente "<<s<<" sin respuesta — cerrando."<<std::endl;
            close(s);
        }
    }
}

// ============================================================
//  HandleClient
// ============================================================
void HandleClient(int clientSocket){
    char buffer[65536]; std::string accum;
    std::string currentNick=""; bool authed=false; std::string currentHwid="";
    bool isAdmin=false;

    SendTo(clientSocket,"SYSTEM: UPLINK ESTABLISHED.");

    while(true){
        int b=recv(clientSocket,buffer,65535,0);
        if(b<=0) break;
        buffer[b]='\0'; accum+=buffer;
        if(accum.size()>1024*1024){ accum.clear(); continue; }

        size_t pos;
        while((pos=accum.find('\n'))!=std::string::npos){
            std::string raw=accum.substr(0,pos); accum.erase(0,pos+1);
            raw.erase(std::remove(raw.begin(),raw.end(),'\r'),raw.end());
            if(raw.empty()) continue;

            // Actualizar lastSeen
            if(authed){
                std::lock_guard<std::mutex> lk(g_ClientsMutex);
                auto it=g_Clients.find(clientSocket);
                if(it!=g_Clients.end()) it->second.lastSeen=time(nullptr);
            }

            // --- PONG (respuesta a keepalive) ---
            if(raw=="PONG"){ continue; }

            // --- LOGIN ---
            if(raw.find("[LOGIN]:")==0){
                std::stringstream ss(raw.substr(8));
                std::string u,p,h;
                std::getline(ss,u,':'); std::getline(ss,p,':'); std::getline(ss,h,':');
                currentHwid=h;
                int state=GetLoginState(u,p,h);
                if(state==1){
                    SendTo(clientSocket,"SYSTEM: FIRST LOGIN. CHANGE REQUIRED.");
                    currentNick=u;
                } else if(state==0){
                    SendTo(clientSocket,"SYSTEM: ACCESO CONCEDIDO.");
                    currentNick=u; authed=true;
                    isAdmin=(u.find("admin")!=std::string::npos);
                    {std::lock_guard<std::mutex> lk(g_ClientsMutex);
                     g_Clients[clientSocket]={clientSocket,u,true,time(nullptr)};}
                    Broadcast("SYSTEM: [+] NODE "+u+" UPLINKED.");
                    BroadcastUsers();
                } else if(state==-3){
                    SendTo(clientSocket,"SYSTEM: ACCESO BLOQUEADO. Intenta en 5 minutos.");
                } else if(state==-2){
                    SendTo(clientSocket,"SYSTEM: HWID NO RECONOCIDO.");
                } else {
                    SendTo(clientSocket,"SYSTEM: CREDENCIALES INCORRECTAS.");
                }
            }
            // --- CHANGE ---
            else if(raw.find("[CHANGE]:")==0 && !currentNick.empty()){
                std::stringstream ss(raw.substr(9));
                std::string nu,np;
                std::getline(ss,nu,':'); std::getline(ss,np,':');
                if(UpdateUser(currentNick,nu,np))
                    SendTo(clientSocket,"SYSTEM: ACTUALIZADO. RECONECTA.");
            }
            // --- MENSAJE PRIVADO ---
            else if(raw.find("[PM]:")==0 && authed){
                // Formato: [PM]:target:from:enc_payload
                std::string rest=raw.substr(5);
                size_t s1=rest.find(':'); if(s1==std::string::npos) continue;
                std::string target=rest.substr(0,s1);
                std::string remaining=rest.substr(s1+1);
                size_t s2=remaining.find(':'); if(s2==std::string::npos) continue;
                // from ya lo sabemos: currentNick
                std::string encPayload=remaining.substr(s2+1);
                if(!SendPM(target,currentNick,encPayload))
                    SendTo(clientSocket,"SYSTEM: Usuario '"+target+"' no encontrado.");
            }
            // --- COMANDOS ADMIN ---
            else if(authed && isAdmin){
                // Verificar si es comando de admin
                std::string payload=raw;
                if(raw.find(":")!=std::string::npos)
                    payload=raw.substr(raw.find(":")+1);
                // Desencriptar para ver si es comando
                std::string dec=AESHelper::Decrypt(payload,AES_KEY,AES_IV);
                if(dec.find("/kick ")==0){
                    std::string target=dec.substr(6);
                    KickUser(target);
                    Broadcast("SYSTEM: [ADMIN] NODE "+target+" KICKED.");
                    BroadcastUsers();
                } else if(dec.find("/ban ")==0){
                    // /ban <hwid> <razon>
                    std::string rest=dec.substr(5);
                    size_t sp=rest.find(' ');
                    std::string hwid=sp!=std::string::npos?rest.substr(0,sp):rest;
                    std::string reason=sp!=std::string::npos?rest.substr(sp+1):"admin ban";
                    BanHwid(hwid,reason);
                    SendTo(clientSocket,"SYSTEM: HWID BANEADO: "+hwid);
                } else {
                    LogToFile(currentNick,payload);
                    Broadcast(currentNick+":"+payload);
                }
            }
            // --- MENSAJE NORMAL ---
            else if(authed){
                std::string payload=raw;
                if(raw.find(":")!=std::string::npos)
                    payload=raw.substr(raw.find(":")+1);
                LogToFile(currentNick,payload);
                Broadcast(currentNick+":"+payload);
            }
        }
    }

    {std::lock_guard<std::mutex> lk(g_ClientsMutex); g_Clients.erase(clientSocket);}
    if(!currentNick.empty()&&authed){
        Broadcast("SYSTEM: [-] NODE "+currentNick+" DISCONNECTED.");
        BroadcastUsers();
    }
    close(clientSocket);
}

// ============================================================
//  main
// ============================================================
int main(){
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
#endif
    InitDatabase();

    int srv=socket(AF_INET,SOCK_STREAM,0);
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=INADDR_ANY; addr.sin_port=htons(PORT);
    int opt=1; setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,(const char*)&opt,sizeof(opt));
    bind(srv,(struct sockaddr*)&addr,sizeof(addr));
    listen(srv,20);

    std::cout<<">>> THE RIVER SECURE SERVER ONLINE — PORT "<<PORT<<" <<<"<<std::endl;
    std::cout<<"[SEC] AES-128-CBC activo. Rate-limit: 5 intentos / 5 min."<<std::endl;
    std::cout<<"[HB]  Heartbeat cada 30s, timeout 90s."<<std::endl;

    std::thread(HeartbeatThread).detach();

    while(true){
        sockaddr_in clientAddr{}; socklen_t clientLen=sizeof(clientAddr);
        int client=accept(srv,(struct sockaddr*)&clientAddr,&clientLen);
        if(client<0) continue;
        char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET,&clientAddr.sin_addr,ip,sizeof(ip));
        std::cout<<"[CON] Nueva conexion: "<<ip<<std::endl;
        std::thread(HandleClient,client).detach();
    }
    return 0;
}
