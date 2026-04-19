#include "client/chat_client.h"

#include <chrono>
#include <fstream>
#include <mutex>
#include <vector>

#include "common/security_utils.h"
#include "common/shared_config.h"
#include "common/tor_connection.h"
#include "include/aes.h"

namespace {

std::mutex gClientLogMutex;

void AppendClientLog(const std::string& line) {
    std::lock_guard<std::mutex> lock(gClientLogMutex);
    std::ofstream out("client_runtime.log", std::ios::app);
    if (!out.is_open()) return;
    out << line << "\n";
}

}

ChatClient::ChatClient(ChatState& state) : state_(state) {}

ChatClient::~ChatClient() {
    Stop();
}

void ChatClient::Start() {
    if (networkThread_.joinable()) return;
    stopRequested_.store(false);
    state_.SetStatusDetail("Inicializando cliente seguro...");
    state_.ClearLastError();
    networkThread_ = std::thread(&ChatClient::NetworkLoop, this);
}

void ChatClient::Stop() {
    stopRequested_.store(true);
    CloseCurrentSocket();
    if (networkThread_.joinable()) networkThread_.join();
}

void ChatClient::SetCurrentUser(const std::string& user) {
    std::lock_guard<std::mutex> lock(identityMutex_);
    currentUser_ = user;
}

std::string ChatClient::CurrentUser() const {
    std::lock_guard<std::mutex> lock(identityMutex_);
    return currentUser_;
}

void ChatClient::QueueAutoLogin(const std::string& user, const std::string& pass) {
    std::lock_guard<std::mutex> lock(reloginMutex_);
    queuedLoginUser_ = user;
    queuedLoginPass_ = pass;
}

bool ChatClient::ConsumeQueuedAutoLogin(std::string& user, std::string& pass) {
    std::lock_guard<std::mutex> lock(reloginMutex_);
    if (queuedLoginUser_.empty() || queuedLoginPass_.empty()) return false;
    user = queuedLoginUser_;
    pass = queuedLoginPass_;
    queuedLoginUser_.clear();
    queuedLoginPass_.clear();
    return true;
}

int ChatClient::SendRawLine(const std::string& payload) {
    std::lock_guard<std::mutex> lock(socketMutex_);
    if (!IsSocketValid(socket_)) return -1;
    return send(socket_, payload.c_str(), (int)payload.size(), 0);
}

void ChatClient::CloseCurrentSocket() {
    std::lock_guard<std::mutex> lock(socketMutex_);
    if (!IsSocketValid(socket_)) return;
    CloseSocketHandle(socket_);
    socket_ = kInvalidSocket;
}

bool ChatClient::SendLogin(const std::string& user, const std::string& pass) {
    SetCurrentUser(user);
    state_.ClearLastError();
    state_.SetAuthActionPending(true);
    state_.SetCredentialChangePending(false);
    state_.SetConnectionState(ConnState::AUTHENTICATING);
    state_.SetStatusDetail("Autenticando credenciales...");
    AppendClientLog("SendLogin user=" + user);
    if (SendRawLine("[LOGIN]:" + user + ":" + pass + ":" + MakeStableMachineId() + "\n") < 0) {
        state_.SetAuthActionPending(false);
        state_.SetLastError("No hay canal disponible para enviar el login.");
        state_.SetStatusDetail("Sin enlace activo hacia el servidor.");
        return false;
    }
    return true;
}

bool ChatClient::SendFirstLoginChange(const std::string& newUser, const std::string& newPass) {
    state_.ClearLastError();
    state_.SetCredentialChangePending(true);
    state_.SetConnectionState(ConnState::UPDATING_CREDENTIALS);
    state_.SetStatusDetail("Actualizando identidad inicial...");
    QueueAutoLogin(newUser, newPass);
    if (SendRawLine("[CHANGE]:" + newUser + ":" + newPass + "\n") < 0) {
        state_.SetCredentialChangePending(false);
        QueueAutoLogin("", "");
        state_.SetLastError("No se pudo enviar el cambio inicial de credenciales.");
        state_.SetStatusDetail("Sin enlace activo hacia el servidor.");
        return false;
    }
    return true;
}

bool ChatClient::SendPing() {
    if (SendRawLine("PING\n") < 0) {
        state_.SetLastError("No se pudo enviar PING al servidor.");
        return false;
    }
    return true;
}

bool ChatClient::SendChatMessage(const std::string& user, const std::string& input) {
    std::string enc = AESHelper::Encrypt(input, river::kAesKey, "");
    if (SendRawLine(user + ":" + enc + "\n") < 0) {
        state_.SetLastError("No se pudo enviar el mensaje. Canal no disponible.");
        return false;
    }
    return true;
}

bool ChatClient::SendPrivateMessage(const std::string& fromUser, const std::string& target, const std::string& message) {
    std::string enc = AESHelper::Encrypt(message, river::kAesKey, "");
    if (SendRawLine("[PM]:" + target + ":" + fromUser + ":" + enc + "\n") < 0) {
        state_.SetLastError("No se pudo enviar el mensaje privado.");
        return false;
    }
    return true;
}

void ChatClient::ReceiveLoop(SocketHandle sock) {
    char buf[16384];
    std::string accum;
    AppendClientLog("ReceiveLoop start");
    while (!stopRequested_.load()) {
        int bytes = recv(sock, buf, 16383, 0);
        if (bytes == 0) {
            AppendClientLog("ReceiveLoop recv=0 peer closed");
            break;
        }
        if (bytes < 0) {
#ifdef _WIN32
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) {
                AppendClientLog("ReceiveLoop timeout");
                continue;
            }
            AppendClientLog("ReceiveLoop error=" + std::to_string(err));
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            AppendClientLog("ReceiveLoop error=" + std::to_string(errno));
#endif
            break;
        }

        buf[bytes] = '\0';
        AppendClientLog("ReceiveLoop bytes=" + std::to_string(bytes));
        accum += buf;
        if (accum.size() > 1024 * 1024) accum.clear();

        size_t pos = 0;
        while ((pos = accum.find('\n')) != std::string::npos) {
            std::string line = accum.substr(0, pos);
            accum.erase(0, pos + 1);

            if (line == "PING") {
                AppendClientLog("ReceiveLoop line=PING");
                SendRawLine("PONG\n");
            } else if (line.find("FIRST LOGIN") != std::string::npos) {
                AppendClientLog("ReceiveLoop line=FIRST LOGIN");
                state_.SetAuthActionPending(false);
                state_.SetCredentialChangePending(false);
                state_.SetMustChangeCredentials(true);
                state_.SetConnectionState(ConnState::FIRST_LOGIN_REQUIRED);
                state_.SetStatusDetail("Primer acceso detectado. Debes cambiar ID y clave.");
                state_.ClearLastError();
            } else if (line.find("ACCESO CONCEDIDO") != std::string::npos) {
                AppendClientLog("ReceiveLoop line=ACCESO CONCEDIDO");
                QueueAutoLogin("", "");
                state_.SetAuthenticated(true);
                state_.SetMustChangeCredentials(false);
                state_.SetAuthActionPending(false);
                state_.SetCredentialChangePending(false);
                state_.SetConnectionState(ConnState::AUTHENTICATED);
                state_.SetStatusDetail("Canal seguro autenticado.");
                state_.ClearLastError();
            } else if (line.find("UPLINK ESTABLISHED") != std::string::npos) {
                AppendClientLog("ReceiveLoop line=UPLINK ESTABLISHED");
                state_.SetConnectionState(ConnState::TOR_READY);
                state_.SetStatusDetail("Canal Tor establecido. Esperando login.");
                state_.ClearLastError();
                std::string queuedUser;
                std::string queuedPass;
                if (ConsumeQueuedAutoLogin(queuedUser, queuedPass)) {
                    AppendClientLog("ReceiveLoop auto-login user=" + queuedUser);
                    SendLogin(queuedUser, queuedPass);
                }
            } else if (line.find("ACTUALIZADO. RECONECTA") != std::string::npos) {
                AppendClientLog("ReceiveLoop line=ACTUALIZADO");
                state_.SetMustChangeCredentials(false);
                state_.SetAuthActionPending(false);
                state_.SetCredentialChangePending(false);
                state_.SetConnectionState(ConnState::RECONNECTING);
                state_.SetStatusDetail("Credenciales actualizadas. Reautenticando en cuanto el canal vuelva a estar listo...");
                state_.ClearLastError();
            } else if (line.find("ACTUALIZADO") != std::string::npos) {
                AppendClientLog("ReceiveLoop line=ACTUALIZADO SIMPLE");
                QueueAutoLogin("", "");
                state_.SetMustChangeCredentials(false);
                state_.SetAuthActionPending(false);
                state_.SetCredentialChangePending(false);
                state_.SetStatusDetail("Credenciales actualizadas. Finalizando acceso...");
                state_.ClearLastError();
            } else if (line.find("CREDENCIALES INCORRECTAS") != std::string::npos) {
                AppendClientLog("ReceiveLoop line=CREDENCIALES INCORRECTAS");
                state_.SetAuthActionPending(false);
                state_.SetConnectionState(ConnState::TOR_READY);
                state_.SetStatusDetail("Canal Tor listo. Esperando nuevas credenciales.");
                state_.SetLastError("Credenciales incorrectas.");
            } else if (line.find("HWID NO RECONOCIDO") != std::string::npos) {
                AppendClientLog("ReceiveLoop line=HWID NO RECONOCIDO");
                state_.SetAuthActionPending(false);
                state_.SetConnectionState(ConnState::TOR_READY);
                state_.SetStatusDetail("Canal Tor listo. Acceso denegado por HWID.");
                state_.SetLastError("Esta maquina no coincide con el HWID autorizado.");
            } else if (line.find("ACCESO BLOQUEADO") != std::string::npos) {
                AppendClientLog("ReceiveLoop line=ACCESO BLOQUEADO");
                state_.SetAuthActionPending(false);
                state_.SetCredentialChangePending(false);
                state_.SetConnectionState(ConnState::TOR_READY);
                state_.SetStatusDetail("Canal Tor listo. Acceso bloqueado.");
                state_.SetLastError("Acceso bloqueado para esta maquina.");
            } else if (line.find("ERROR ACTUALIZANDO USUARIO") != std::string::npos) {
                AppendClientLog("ReceiveLoop line=ERROR ACTUALIZANDO USUARIO");
                state_.SetCredentialChangePending(false);
                state_.SetConnectionState(ConnState::FIRST_LOGIN_REQUIRED);
                state_.SetStatusDetail("No se pudo completar el cambio inicial.");
                state_.SetLastError("No se pudo actualizar el usuario o la clave.");
            } else if (line.find("[PM]:") == 0) {
                AppendClientLog("ReceiveLoop line=PM");
                state_.AddIncomingWireMessage(line.substr(5), CurrentUser(), true);
            } else {
                AppendClientLog("ReceiveLoop line=" + line);
                state_.AddIncomingWireMessage(line, CurrentUser(), false);
            }
        }
    }
    AppendClientLog("ReceiveLoop end");
}

void ChatClient::NetworkLoop() {
    AppendClientLog("NetworkLoop start");
    while (!stopRequested_.load()) {
        CloseCurrentSocket();
        bool hadIdentity = !CurrentUser().empty();
        state_.SetConnectionState(hadIdentity ? ConnState::RECONNECTING : ConnState::CONNECTING);
        state_.SetAuthenticated(false);
        state_.SetMustChangeCredentials(false);
        state_.SetAuthActionPending(false);
        state_.SetCredentialChangePending(false);
        state_.SetStatusDetail(hadIdentity ? "Restableciendo enlace Tor..." : "Conectando a la red Tor...");
        AppendClientLog("NetworkLoop CONNECTING");

        TorEndpoint endpoint{
            river::kTorProxyIp,
            river::kTorProxyPort,
            river::kOnionAddress,
            (unsigned short)river::kTorOnionPort
        };
        SocketHandle sock = ConnectViaTor(endpoint);
        if (!IsSocketValid(sock)) {
            AppendClientLog("NetworkLoop ConnectViaTor failed");
            state_.SetConnectionState(ConnState::DISCONNECTED);
            state_.SetStatusDetail("No se pudo abrir un circuito onion hacia el servidor.");
            state_.SetLastError("Tor no disponible o hidden service sin respuesta.");
            for (int i = 0; i < 50 && !stopRequested_.load(); ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(socketMutex_);
            socket_ = sock;
        }
        AppendClientLog("NetworkLoop TOR_OK");
        state_.SetConnectionState(ConnState::TOR_READY);
        state_.SetStatusDetail("Canal Tor listo. Esperando banner del servidor...");
        state_.ClearLastError();
        ReceiveLoop(sock);
        CloseCurrentSocket();
        state_.SetAuthenticated(false);
        state_.SetConnectionState(ConnState::DISCONNECTED);
        state_.SetAuthActionPending(false);
        state_.SetCredentialChangePending(false);
        state_.SetStatusDetail("Canal cerrado. Reintentando enlace...");
        AppendClientLog("NetworkLoop DISCONNECTED");
    }
    AppendClientLog("NetworkLoop end");
}
