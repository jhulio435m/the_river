#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

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

    // Admin maintenance helpers.
    assert(record.hwid.empty());
    assert(repo.UpdateUserHwid("operator1", "hwid-operator"));
    assert(repo.FindUserByUsername("operator1").hwid == "hwid-operator");
    assert(repo.ResetUserHwid("operator1"));
    assert(repo.FindUserByUsername("operator1").hwid.empty());
    assert(!repo.ResetUserHwid("ghost-user"));

    assert(repo.BanHwid("hwid-banned", "spam"));
    const std::vector<BannedHwidRecord> bans = repo.ListBannedHwids();
    assert(bans.size() == 1);
    assert(bans[0].hwid == "hwid-banned");
    assert(bans[0].reason == "spam");
    assert(bans[0].bannedAt > 0);
    assert(repo.UnbanHwid("hwid-banned"));
    assert(repo.ListBannedHwids().empty());

    std::string second;
    assert(repo.CreateNextUser(second));
    const std::vector<UserSummary> users = repo.ListUsers();
    assert(users.size() == 3);
    bool sawAdmin = false;
    bool sawPending = false;
    for (const auto& user : users) {
        if (user.username == "admin") sawAdmin = user.isAdmin;
        if (user.username == second) sawPending = user.firstLoginPending && !user.hwidBound;
    }
    assert(sawAdmin);
    assert(sawPending);

    assert(!repo.DeleteUser("admin"));
    assert(repo.DeleteUser(second));
    assert(!repo.UserExists(second));
    assert(repo.ListUsers().size() == 2);

    repo.Close();
    std::remove(dbPath.c_str());
}

}  // namespace

int main() {
    TestUserRepositoryLifecycle();
    return 0;
}
