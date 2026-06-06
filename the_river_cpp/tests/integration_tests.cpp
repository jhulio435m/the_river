#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "common/security_utils.h"
#include "server/user_repository.h"

namespace {

std::string TempDbPath() {
    const char* tmp = std::getenv("TMPDIR");
    std::string base = tmp != nullptr && tmp[0] != '\0' ? tmp : "/tmp";
    return base + "/the_river_integration_" + RandomHex(8) + ".db";
}

void TestUserRepositoryLifecycle() {
    setenv("THE_RIVER_ADMIN_USER", "admin", 1);
    setenv("THE_RIVER_ADMIN_BOOTSTRAP_PASSWORD", "admin-bootstrap-key", 1);
    setenv("THE_RIVER_NEW_USER_PASSWORD", "initial-user-key", 1);

    const std::string dbPath = TempDbPath();

    UserRepository repo;
    assert(repo.Open(dbPath));
    assert(repo.InitSchema());

    std::string adminHash;
    assert(repo.GetPasswordHash("admin", adminHash));
    assert(VerifyPasswordHash("admin-bootstrap-key", adminHash));

    std::string username;
    assert(repo.CreateNextUser(username));
    assert(!username.empty());
    assert(repo.UserExists(username));

    std::string userHash;
    assert(repo.GetPasswordHash(username, userHash));
    assert(VerifyPasswordHash("initial-user-key", userHash));

    assert(repo.CompleteFirstLogin(username, "operator1", "operator-strong-key"));
    assert(repo.UserExists("operator1"));

    UserRecord record = repo.FindUserByUsername("operator1");
    assert(record.found);
    assert(record.firstLogin == 0);
    assert(!record.isAdmin);

    repo.Close();
    std::remove(dbPath.c_str());
}

}  // namespace

int main() {
    TestUserRepositoryLifecycle();
    return 0;
}
