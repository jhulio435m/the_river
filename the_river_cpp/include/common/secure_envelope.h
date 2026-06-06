#pragma once

#include <string>

namespace river {

std::string SealPayload(const std::string& plainText);
bool OpenPayload(const std::string& sealedPayload, std::string& plainText);
std::string SealPayloadBinary(const std::string& plainText);
bool OpenPayloadBinary(const std::string& sealedPayload, std::string& plainText);

}
