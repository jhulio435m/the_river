#pragma once

// Shared helpers for the end-to-end tests (POSIX only): check counters, temp
// dirs, free ports, child processes (the real server binary or a re-executed
// test binary) and waiting for a TCP port.

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

extern char** environ;

namespace e2e {

inline int g_failures = 0;
inline int g_checks = 0;

#define E2E_CHECK(cond, what)                                                          \
    do {                                                                               \
        ++::e2e::g_checks;                                                             \
        if (!(cond)) {                                                                 \
            ++::e2e::g_failures;                                                       \
            std::cerr << "FAIL: " << what << " (" #cond ") line " << __LINE__ << std::endl; \
        } else {                                                                       \
            std::cout << "ok: " << what << std::endl;                                  \
        }                                                                              \
    } while (0)

inline int Summary() {
    std::cout << "\n" << (g_checks - g_failures) << "/" << g_checks << " checks passed" << std::endl;
    return g_failures == 0 ? 0 : 1;
}

inline std::string MakeTempDir(const std::string& prefix) {
    const char* base = std::getenv("TMPDIR");
    std::string pattern = std::string(base && *base ? base : "/tmp") + "/" + prefix + "XXXXXX";
    std::vector<char> buf(pattern.begin(), pattern.end());
    buf.push_back('\0');
    if (mkdtemp(buf.data()) == nullptr) {
        std::perror("mkdtemp");
        std::exit(2);
    }
    return std::string(buf.data());
}

inline void RemoveTree(const std::string& dir) {
    if (dir.empty() || dir == "/") return;
    const std::string cmd = "rm -rf '" + dir + "'";
    if (std::system(cmd.c_str()) != 0) std::cerr << "warning: could not remove " << dir << std::endl;
}

// Absolute path (children chdir into their temp dir before exec).
inline std::string AbsolutePath(const std::string& path) {
    char buf[PATH_MAX] = {0};
    if (realpath(path.c_str(), buf) == nullptr) return path;
    return std::string(buf);
}

inline bool FileExists(const std::string& path) {
    struct stat st {};
    return ::stat(path.c_str(), &st) == 0;
}

inline std::string ReadFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

inline bool WriteFile(const std::string& path, const std::string& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    return static_cast<bool>(out);
}

inline std::string TailLines(const std::string& text, int n) {
    std::size_t pos = text.size();
    for (int i = 0; i <= n && pos != std::string::npos && pos > 0; ++i) pos = text.rfind('\n', pos - 1);
    return (pos == std::string::npos || pos == 0) ? text : text.substr(pos + 1);
}

// Listening socket on 127.0.0.1 (port 0 = ephemeral). Returns -1 on error.
inline int ListenLocal(int port, int& boundPort) {
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -1;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 || listen(s, 16) != 0) {
        close(s);
        return -1;
    }
    socklen_t len = sizeof(a);
    getsockname(s, reinterpret_cast<sockaddr*>(&a), &len);
    boundPort = ntohs(a.sin_port);
    return s;
}

// A currently free TCP port on 127.0.0.1 (released before returning).
inline int FreePort() {
    int port = 0;
    int s = ListenLocal(0, port);
    if (s < 0) {
        std::cerr << "cannot allocate a free port" << std::endl;
        std::exit(2);
    }
    close(s);
    return port;
}

inline int ConnectLocal(int port) {
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -1;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        close(s);
        return -1;
    }
    return s;
}

// Polls until something accepts on 127.0.0.1:port. A successful probe opens a
// connection the server sees and drops immediately, which it tolerates.
inline bool WaitForPort(int port, int timeoutMs, pid_t mustStayAlive = -1) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (mustStayAlive > 0) {
            int status = 0;
            if (waitpid(mustStayAlive, &status, WNOHANG) == mustStayAlive) return false;
        }
        int s = ConnectLocal(port);
        if (s >= 0) {
            close(s);
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

struct ChildOptions {
    std::vector<std::string> argv;
    std::string cwd;
    std::map<std::string, std::string> setEnv;
    std::vector<std::string> unsetEnv;
    std::string stdoutFile;  // empty: inherit (unless pipes requested)
    bool pipeStdin = false;
    bool pipeStdout = false;
};

struct Child {
    pid_t pid = -1;
    int stdinFd = -1;   // write end, when pipeStdin
    int stdoutFd = -1;  // read end, when pipeStdout
};

inline Child Spawn(const ChildOptions& opt) {
    int inPipe[2] = {-1, -1};
    int outPipe[2] = {-1, -1};
    if (opt.pipeStdin && pipe2(inPipe, O_CLOEXEC) != 0) std::exit(2);
    if (opt.pipeStdout && pipe2(outPipe, O_CLOEXEC) != 0) std::exit(2);
    // Everything the child needs is prepared before fork(): the parent has
    // threads, so the child only calls async-signal-safe functions before exec.
    std::map<std::string, std::string> env;
    for (char** e = environ; e != nullptr && *e != nullptr; ++e) {
        const char* eq = std::strchr(*e, '=');
        if (eq != nullptr) env[std::string(*e, static_cast<std::size_t>(eq - *e))] = eq + 1;
    }
    for (const auto& name : opt.unsetEnv) env.erase(name);
    for (const auto& kv : opt.setEnv) env[kv.first] = kv.second;
    std::vector<std::string> envStrings;
    for (const auto& kv : env) envStrings.push_back(kv.first + "=" + kv.second);
    std::vector<char*> envp;
    for (auto& e : envStrings) envp.push_back(const_cast<char*>(e.c_str()));
    envp.push_back(nullptr);
    std::vector<char*> args;
    for (const auto& a : opt.argv) args.push_back(const_cast<char*>(a.c_str()));
    args.push_back(nullptr);
    int outFileFd = -1;
    if (!opt.pipeStdout && !opt.stdoutFile.empty())
        outFileFd = open(opt.stdoutFile.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

    std::cout.flush();
    std::cerr.flush();
    pid_t pid = fork();
    if (pid < 0) {
        std::perror("fork");
        std::exit(2);
    }
    if (pid == 0) {
        if (!opt.cwd.empty() && chdir(opt.cwd.c_str()) != 0) _exit(127);
        if (opt.pipeStdin) dup2(inPipe[0], STDIN_FILENO);
        if (opt.pipeStdout) {
            dup2(outPipe[1], STDOUT_FILENO);
        } else if (outFileFd >= 0) {
            dup2(outFileFd, STDOUT_FILENO);
            dup2(outFileFd, STDERR_FILENO);
        }
        execve(args[0], args.data(), envp.data());
        _exit(127);
    }
    if (outFileFd >= 0) close(outFileFd);
    Child c;
    c.pid = pid;
    if (opt.pipeStdin) {
        close(inPipe[0]);
        c.stdinFd = inPipe[1];
    }
    if (opt.pipeStdout) {
        close(outPipe[1]);
        c.stdoutFd = outPipe[0];
    }
    return c;
}

// Waits up to timeoutMs for the child; returns true and its status if it exited.
inline bool WaitChild(pid_t pid, int timeoutMs, int& status) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (true) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) return true;
        if (r < 0) return false;
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

// SIGTERM, wait, SIGKILL as a last resort. Returns the exit code, or -1 when the
// child did not exit normally within timeoutMs (it is killed then).
inline int TerminateChild(pid_t pid, int timeoutMs) {
    if (pid <= 0) return -1;
    kill(pid, SIGTERM);
    int status = 0;
    if (WaitChild(pid, timeoutMs, status)) return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    return -1;
}

}  // namespace e2e
