#include <iostream>
#include <vector>
#include <string>
#include <thread>
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

// --- CONFIGURACION ---
std::string ONION_ADDR = "3k4kzzkhiy6oyitin3g3wuy7hs6sf7tmcqdipe2vwaqxfyiggedltiid.onion";
std::string PROXY_IP   = "127.0.0.1";
int         PROXY_PORT = 9050;
const std::string AES_KEY = "RIVER_SECURE_KEY";   // 16 bytes
const std::string AES_IV  = "";

int g_AdminSocket = -1;

bool ConnectTor(){
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
#endif
    g_AdminSocket=socket(AF_INET,SOCK_STREAM,0);
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_port=htons(PROXY_PORT);
    inet_pton(AF_INET,PROXY_IP.c_str(),&addr.sin_addr);
    if(connect(g_AdminSocket,(struct sockaddr*)&addr,sizeof(addr))!=0) return false;

    char hello[]={0x05,0x01,0x00}; send(g_AdminSocket,hello,3,0);
    char res[2]; recv(g_AdminSocket,res,2,0);

    std::vector<char> req={0x05,0x01,0x00,0x03};
    req.push_back((char)ONION_ADDR.size());
    for(char c:ONION_ADDR) req.push_back(c);
    req.push_back(0x00); req.push_back(0x50);
    send(g_AdminSocket,req.data(),(int)req.size(),0);
    char reply[10]; recv(g_AdminSocket,reply,10,0);
    return reply[1]==0x00;
}

void Receiver(){
    char buf[4096];
    std::string accum;
    while(true){
        int b=recv(g_AdminSocket,buf,4095,0);
        if(b<=0) break;
        buf[b]='\0';
        accum+=buf;
        size_t pos;
        while((pos=accum.find('\n'))!=std::string::npos){
            std::string line=accum.substr(0,pos); accum.erase(0,pos+1);
            if(line.find("SYSTEM")==std::string::npos && line.find(":")!=std::string::npos){
                size_t sep=line.find(":");
                std::string user=line.substr(0,sep);
                std::string dec=AESHelper::Decrypt(line.substr(sep+1),AES_KEY,AES_IV);
                std::cout<<"\r\033[K["<<user<<"]: "<<dec<<"\nADMIN> "<<std::flush;
            } else if(line.find("[PM]:")==0){
                std::string rest=line.substr(5);
                size_t s1=rest.find(':');
                std::string from=s1!=std::string::npos?rest.substr(0,s1):rest;
                std::string enc=s1!=std::string::npos?rest.substr(s1+1):"";
                std::string dec=AESHelper::Decrypt(enc,AES_KEY,AES_IV);
                std::cout<<"\r\033[K[PM de "<<from<<"]: "<<dec<<"\nADMIN> "<<std::flush;
            } else {
                std::cout<<"\r\033[K"<<line<<"\nADMIN> "<<std::flush;
            }
        }
    }
}

int main(){
    std::cout<<"--- THE RIVER | ADMIN CONSOLE V2.0 ---"<<std::endl;

    // Pedir credenciales en runtime (no hardcodeadas)
    std::string adminUser, adminPass;
    std::cout<<"ADMIN IDENT : "; std::getline(std::cin, adminUser);
    std::cout<<"ADMIN KEY   : "; std::getline(std::cin, adminPass);

    std::cout<<"[*] Conectando..."<<std::endl;
    if(!ConnectTor()){
        // Intentar conexion local
        g_AdminSocket=socket(AF_INET,SOCK_STREAM,0);
        sockaddr_in l{}; l.sin_family=AF_INET; l.sin_port=htons(8888);
        inet_pton(AF_INET,"127.0.0.1",&l.sin_addr);
        if(connect(g_AdminSocket,(struct sockaddr*)&l,sizeof(l))!=0){
            std::cerr<<"[!] Error: No se puede conectar."<<std::endl;
            return 1;
        }
        std::cout<<"[*] Conectado localmente."<<std::endl;
    }

    // Login con credenciales ingresadas
    std::string login="[LOGIN]:"+adminUser+":"+adminPass+":ADMIN_HWID\n";
    send(g_AdminSocket,login.c_str(),(int)login.size(),0);

    std::thread(Receiver).detach();

    std::string input;
    std::cout<<"ADMIN> ";
    while(true){
        std::getline(std::cin,input);
        if(input=="/exit") break;
        if(input.empty()){ std::cout<<"ADMIN> "; continue; }

        std::string enc=AESHelper::Encrypt(input,AES_KEY,AES_IV);
        std::string payload=adminUser+":"+enc+"\n";
        send(g_AdminSocket,payload.c_str(),(int)payload.size(),0);
        std::cout<<"ADMIN> ";
    }

    close(g_AdminSocket);
    return 0;
}
