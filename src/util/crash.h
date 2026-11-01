#pragma once

namespace bpb {

// Installs fatal-signal handlers that print a backtrace before dying.
//
// A heap corruption aborts deep inside free() with nothing but
// "free(): double free detected in tcache 2" -- no file, no line, no clue which
// path corrupted it, and systemd swallows it into the journal where it reads
// like a random restart. The handler below turns that into a stack of addresses
// (with names when the binary is linked -rdynamic).
//
// Deliberately tiny and async-signal-safe: backtrace(), write(2), _exit().
void install_crash_handler();

} // namespace bpb
