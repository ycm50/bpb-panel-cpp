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

// bpb --passwd [user] <password>        set the credential (writes <data>/passwd)
// bpb --passwd                          report what is on disk (never the secret)
// bpb --passwd --check [user] <password> verify on disk *and* against the running panel
int run_cli(const std::string& data_dir, int port, const std::vector<std::string>& args,
            bool check_only);

} // namespace bpb::app::passwd
