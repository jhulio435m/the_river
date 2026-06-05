#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>

void Clear() {
    std::cout << "\033[2J\033[H";
}

void DrawLogo() {
    std::cout << "\033[1;32m"; // Verde intenso
    std::cout << R"(
    ████████╗██╗  ██╗███████╗    ██████╗ ██╗██╗   ██╗███████╗██████╗ 
    ╚══██╔══╝██║  ██║██╔════╝    ██╔══██╗██║██║   ██║██╔════╝██╔══██╗
       ██║   ███████║█████╗      ██████╔╝██║██║   ██║█████╗  ██████╔╝
       ██║   ██╔══██║██╔══╝      ██╔══██╗██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
       ██║   ██║  ██║███████╗    ██║  ██║██║ ╚████╔╝ ███████╗██║  ██║
       ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
    )" << "\n";
    std::cout << "\033[0m";
}

void MatrixEffect() {
    Clear();
    DrawLogo();
    std::cout << "\n\033[1;32m[ INITIALIZING ADMIN CONSOLE... ]\033[0m\n";
    const char* chars = "0123456789ABCDEF!@#$%^&*()";
    for(int i=0; i<20; ++i) {
        std::cout << "\033[32m";
        for(int j=0; j<80; ++j) {
            if (rand() % 10 == 0) std::cout << chars[rand() % 26];
            else std::cout << " ";
        }
        std::cout << "\033[0m\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

int main() {
    MatrixEffect();
    return 0;
}
