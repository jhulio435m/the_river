#include "common/shared_config.h"
#include "server/chat_server.h"

int main() {
    ChatServer server(river::DefaultDbFile(), river::DefaultLogFile());
    return server.Run();
}
