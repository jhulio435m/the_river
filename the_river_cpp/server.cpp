#include "common/shared_config.h"
#include "server/chat_server.h"

int main() {
    ChatServer server(river::kDefaultDbFile, river::kDefaultLogFile);
    return server.Run();
}
