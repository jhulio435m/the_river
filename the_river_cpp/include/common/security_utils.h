#pragma once

#include <string>

std::string HashPassword(const std::string& input);
std::string RandomHex(std::size_t bytes);
std::string HmacSha256Hex(const std::string& key, const std::string& message);
std::string MakePasswordHash(const std::string& password);
std::string DerivePasswordVerifier(const std::string& password, const std::string& hashSpec);
bool VerifyPasswordHash(const std::string& password, const std::string& storedHash);
bool IsValidUsername(const std::string& username);
bool IsStrongEnoughPassword(const std::string& password);
std::string MakeStableMachineId();
