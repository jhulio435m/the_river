#pragma once

#include <string>

namespace river {

std::string SealPayload(const std::string& plainText);
bool OpenPayload(const std::string& sealedPayload, std::string& plainText);

}
