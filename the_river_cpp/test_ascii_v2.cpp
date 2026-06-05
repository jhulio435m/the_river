#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <vector>

void Clear() {
    std::cout << "\033[2J\033[H";
}

void Typewriter(const std::string& text, int delay_ms = 30) {
    for (char c : text) {
        std::cout << c << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }
    std::cout << std::endl;
}

void DrawLogo() {
    std::cout << "\033[1;32m"; // Green
    std::cout << "  _______ _    _ ______   _____  _______      ________ _____  " << std::endl;
    std::cout << " |__   __| |  | |  ____| |  __ \\|_   _\\ \\    / /  ____|  __ \\ " << std::endl;
    std::cout << "    | |  | |__| | |__    | |__) | | |  \\ \\  / /| |__  | |__) |" << std::endl;
    std::cout << "    | |  |  __  |  __|   |  _  /  | |   \\ \\/ / |  __| |  _  / " << std::endl;
    std::cout << "    | |  | |  | | |____  | | \\ \\ _| |_   \\  /  | |____| | \\ \\ " << std::endl;
    std::cout << "    |_|  |_|  |_|______| |_|  \\_\\_____|   \\/   |______|_|  \\_\\" << std::endl;
    std::cout << "\033[0m" << std::endl;
}

void BootSequence() {
    Clear();
    DrawLogo();
    std::cout << "\033[1;32m";
    Typewriter("[*] INITIALIZING SECURE LINK...", 50);
    Typewriter("[*] LOADING ENCRYPTION MODULES...", 40);
    Typewriter("[*] BYPASSING FIREWALLS...", 60);
    Typewriter("[*] ESTABLISHING ONION CIRCUIT...", 80);
    std::cout << "\n[ ACCESS GRANTED ]\n\033[0m" << std::endl;
}

int main() {
    BootSequence();
    return 0;
}
