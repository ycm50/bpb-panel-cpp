#include "util/memlimit.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace bpb::util {

int default_memory_max_mb() { return kDefaultMemoryMaxMb; }

bool parse_memory_max_mb(const char* text, int& mb, std::string& error) {
    mb = 0;
    if (!text || !*text) {
        error = "empty value";
        return false;
    }
    // Digit prefix only: strtol would accept "0x40", "-1" and " 64", and a
    // negative ceiling silently means "unlimited" to systemd.
    const char* p = text;
    if (*p == '+') ++p;
    const char* digits = p;
    long value = 0;
    while (*p >= '0' && *p <= '9') {
        value = value * 10 + (*p - '0');
        if (value > kMaxMemoryMaxMb) {
            error = "value too large (max " + std::to_string(kMaxMemoryMaxMb) + " MiB)";
            return false;
        }
        ++p;
    }
    if (p == digits) {
        error = std::string("not a number: '") + text + "'";
        return false;
    }
    // Optional unit suffix. Anything else after the number is a typo worth
    // reporting: "--mem-max 64MB" would otherwise be read as 64 and hide the
    // mistake.
    std::string suffix;
    while (*p) {
        suffix.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(*p))));
        ++p;
    }
    if (!suffix.empty() && suffix != "m" && suffix != "mb" && suffix != "mib") {
        error = std::string("unknown unit '") + suffix + "' (use MiB, e.g. 64)";
        return false;
    }
    if (value < kMinMemoryMaxMb) {
        error = "too small (min " + std::to_string(kMinMemoryMaxMb) + " MiB)";
        return false;
    }
    mb = static_cast<int>(value);
    return true;
}

std::string memory_max_systemd_value(int mb) { return std::to_string(mb) + "M"; }

std::string memory_high_systemd_value(int mb) {
    // 85%: reclaim starts while there is still room to make progress, so the
    // cgroup throttles the newest session instead of the kernel killing the
    // process (which is what 40M of hard ceiling did).
    int high = static_cast<int>(static_cast<long long>(mb) * 85 / 100);
    if (high < kMinMemoryMaxMb) high = kMinMemoryMaxMb;
    return std::to_string(high) + "M";
}

std::size_t memory_max_bytes(int mb) {
    if (mb <= 0) mb = kDefaultMemoryMaxMb;
    return static_cast<std::size_t>(mb) * 1024u * 1024u;
}

} // namespace bpb::util
