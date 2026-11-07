#pragma once
#include <cstdarg>

namespace bpb {
namespace log {

// Runtime log switch.
//
// The relay used to narrate everything: one three hour run produced ~470k
// journal lines ("N stream(s), down=... up=...", "request GET /vl", one line per
// second per stream, plus a frame trace). None of that is needed by an operator
// who just wants the tunnel to work, and on a small VPS the journal writes cost
// real CPU. So logging is now a switch and it is OFF out of the box: the default
// level is kError, which means a healthy install prints nothing at all but a
// genuine failure still says why it failed.
//
// Turn it on with BPB_LOG=<level> in the environment or --log <level> on the
// command line (the command line wins):
//
//     bpb --log info      registration, edge connection, tunnel hostname
//     bpb --log debug     per request and per second accounting
//     bpb --log trace     every HTTP/2 frame (was BPB_TUNNEL_TRACE=1)
//
// The old environment variables still work: BPB_TRACE / BPB_TUNNEL_TRACE /
// BPB_WG_TRACE / BPB_WS_TRACE all mean --log trace.
enum Level : int {
    kOff = 0,
    kError = 1,
    kWarn = 2,
    kInfo = 3,
    kDebug = 4,
    kTrace = 5,
};

// Level currently in effect. Never changes after startup in practice, but it is
// atomic so a test (or a future panel switch) can flip it at runtime.
int level();
void set_level(int lvl);

// Resolves the effective level once: CLI value (or -1 when absent) first, then
// BPB_LOG, then the built-in default. Returns the level now in effect.
int init(int cli_level);
bool enabled(int lvl);

bool parse_level(const char* text, int& out);
const char* level_name(int lvl);

// One line per call, always newline terminated, serialised with flockfile so
// two threads cannot interleave half a line.
void write(int lvl, const char* fmt, ...);
void error(const char* fmt, ...);
void warn(const char* fmt, ...);
void info(const char* fmt, ...);
void debug(const char* fmt, ...);

} // namespace log
} // namespace bpb
