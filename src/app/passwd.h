#pragma once
#include <string>
#include <vector>

namespace bpb::app::passwd {

// Panel credential, kept in the data directory next to config.json:
//
//     <data>/passwd            mode 0600, one line:
//     admin:$sha256$<salt_hex>$<hash_hex>
//
// Why a separate file instead of settings.json: the settings document is synced
// to the browser, copied around with the panel and rewritten by every settings
// save, so a plaintext password in it leaks and drifts. The hash lives here, is
// never rendered by any endpoint, and survives a settings reset.
struct Entry {
    std::string user;
    std::string salt;
    std::string hash;
    bool valid() const { return !user.empty() && !hash.empty(); }
};

std::string path_for(const std::string& data_dir);

// Reads the entry. Returns false when the file is missing or unparsable.
bool load(const std::string& data_dir, Entry& out);

// Writes user + salted SHA-256(password). Creates the data directory if needed.
bool save(const std::string& data_dir, const std::string& user, const std::string& password,
          std::string& error);

// Constant-time check of user + password against the file.
bool verify(const std::string& data_dir, const std::string& user, const std::string& password);

// Same check without naming the user. A subscription URL can only afford one
// query parameter (the password), and the account name is already on disk.
bool verify_password(const std::string& data_dir, const std::string& password);

// Guarantees "there is always a credential". Called once at startup, before the
// listener opens: a panel that answers subscription URLs with no secret in front
// of it hands the whole node to whoever finds the domain. Writes a random
// password when <data>/passwd is missing or empty and returns it in `generated`
// so the caller can print it exactly once. An existing file is never touched.
//
// Returns false (and sets `error`) only when the credential is missing and a new
// one cannot be written; the caller is expected to exit in that case rather than
// serve an unauthenticated panel.
bool ensure_credential(const std::string& data_dir, const std::string& user,
                       std::string& generated, std::string& error);

// bpb --passwd [user] <password>        set the credential (writes <data>/passwd)
// bpb --passwd                          report what is on disk (never the secret)
// bpb --passwd --check [user] <password> verify on disk *and* against the running panel
int run_cli(const std::string& data_dir, int port, const std::vector<std::string>& args,
            bool check_only);

} // namespace bpb::app::passwd
