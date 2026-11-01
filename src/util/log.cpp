#include "util/log.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>

namespace bpb {
namespace log {
namespace {

std::atomic<int> g_level{kError};

// A mutex rather than flockfile(): glibc and musl have it, MinGW-UCRT does not,
// and all it buys us is that two threads cannot interleave half a line.
std::mutex g_mutex;

void emit(int lvl, const char* fmt, va_list ap) {
    if (!enabled(lvl)) return;
    std::lock_guard<std::mutex> lock(g_mutex);
    std::vfprintf(stderr, fmt, ap);
    std::fputc('\n', stderr);
}

} // namespace

int level() { return g_level.load(std::memory_order_relaxed); }

void set_level(int lvl) {
    if (lvl < kOff) lvl = kOff;
    if (lvl > kTrace) lvl = kTrace;
    g_level.store(lvl, std::memory_order_relaxed);
}

bool enabled(int lvl) { return lvl <= level() && lvl > kOff; }

const char* level_name(int lvl) {
    switch (lvl) {
        case kOff: return "off";
        case kError: return "error";
        case kWarn: return "warn";
        case kInfo: return "info";
        case kDebug: return "debug";
        case kTrace: return "trace";
        default: return "?";
    }
}

bool parse_level(const char* text, int& out) {
    if (!text || *text == '\0') return false;
    // Numeric forms are accepted so "BPB_LOG=1" (the habit from
    // BPB_TUNNEL_TRACE=1) does something useful instead of silently doing
    // nothing: 1 = info, 2 = debug, 3 = trace, 0 = off.
    if (std::strcmp(text, "0") == 0) { out = kOff; return true; }
    if (std::strcmp(text, "1") == 0) { out = kInfo; return true; }
    if (std::strcmp(text, "2") == 0) { out = kDebug; return true; }
    if (std::strcmp(text, "3") == 0) { out = kTrace; return true; }
    for (int l = kOff; l <= kTrace; ++l) {
        if (std::strcmp(text, level_name(l)) == 0) {
            out = l;
            return true;
        }
    }
    if (std::strcmp(text, "no") == 0 || std::strcmp(text, "false") == 0) {
        out = kOff;
        return true;
    }
    if (std::strcmp(text, "on") == 0 || std::strcmp(text, "yes") == 0 ||
        std::strcmp(text, "true") == 0) {
        out = kInfo;
        return true;
    }
    return false;
}

int init(int cli_level) {
    int lvl = kError;
    const char* env = std::getenv("BPB_LOG");
    int parsed = 0;
    if (env && parse_level(env, parsed)) {
        lvl = parsed;
    } else if (std::getenv("BPB_TRACE") || std::getenv("BPB_TUNNEL_TRACE") ||
               std::getenv("BPB_WG_TRACE") || std::getenv("BPB_WS_TRACE")) {
        // Legacy switches from the tracing era: any of them means "everything".
        lvl = kTrace;
    }
    if (cli_level >= 0) lvl = cli_level;
    set_level(lvl);
    return lvl;
}

void write(int lvl, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    emit(lvl, fmt, ap);
    va_end(ap);
}

void error(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    emit(kError, fmt, ap);
    va_end(ap);
}

void warn(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    emit(kWarn, fmt, ap);
    va_end(ap);
}

void info(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    emit(kInfo, fmt, ap);
    va_end(ap);
}

void debug(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    emit(kDebug, fmt, ap);
    va_end(ap);
}

} // namespace log
} // namespace bpb
