#pragma once
#include <vector>
#include <string>
#include <stdint.h>

// AES-128-CBC standalone (sin dependencias externas)
// El IV se genera aleatoriamente en cada Encrypt y se antepone al ciphertext.
// Formato de salida: base64( IV[16] || AES_CBC(plaintext) )
// El parametro 'iv' se mantiene por compatibilidad de firma pero es ignorado.

class AESHelper {
public:
    static std::string Encrypt(const std::string& plainText,
                               const std::string& key,
                               const std::string& iv = "");
    static std::string Decrypt(const std::string& cipherText,
                               const std::string& key,
                               const std::string& iv = "");
};
