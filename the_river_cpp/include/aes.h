#pragma once
#include <vector>
#include <string>
#include <stdint.h>

// Implementación minimalista de AES-256 para C++ (Modo CBC)
// En un entorno de producción se usaría OpenSSL o mbedTLS,
// pero para portabilidad cruzada usamos una versión compacta.

class AESHelper {
public:
    static std::string Encrypt(const std::string& plainText, const std::string& key, const std::string& iv);
    static std::string Decrypt(const std::string& cipherText, const std::string& key, const std::string& iv);
};
