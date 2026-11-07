#pragma once
// Memory ceiling: one place that decides how much this process may use.
//
// The number has two consumers that must never disagree:
//
//   * install.sh writes it into the systemd unit as MemoryHigh/MemoryMax, which
//     is the kernel-enforced cgroup backstop;
//   * the process itself derives the relay-buffer budget from it, so a burst is
//     turned away by admission control instead of being collected by the OOM
//     killer.
//
// They used to be two unrelated constants: the unit said 40M and the relay
// budget knew nothing about it. On a 100 MB container a burst of downloads then
// reached exactly 40 MB and systemd answered with
//     bpb.service: A process of this unit has been killed by the OOM killer.
//     bpb.service: Failed with result "oom-kill".
// That drops every live session at once, which is the worst possible failure
// mode for a proxy. Keeping both numbers here is what stops the drift: the
// installer asks the binary for the default (bpb --mem-default) instead of
// carrying its own copy.
#include <cstddef>
#include <string>

namespace bpb::util {

// Default ceiling in MiB.
//
// Chosen to leave room on the smallest box this is expected to run on (100 MB
// container): the process itself idles at ~4 MB, the relay pool is bounded
// below, and 64 MiB still leaves ~30 MiB for the kernel, page cache and the
// rest of the container. The old 40 MiB was exactly the peak a burst reached,
// i.e. no headroom at all.
inline constexpr int kDefaultMemoryMaxMb = 64;
// Below this the process cannot hold even a few relay buffers plus its own
// heap; refusing the value is better than starting something that will OOM.
inline constexpr int kMinMemoryMaxMb = 24;
// Sanity bound: a typo like --mem-max 4096 should not silently disable the
// backstop on a small VPS, so the installer is told the number is unusual.
inline constexpr int kMaxMemoryMaxMb = 65536;

// The compiled-in default. A function rather than the constant so the value can
// become configurable at build time without touching callers.
int default_memory_max_mb();

// Parses the value of --mem-max. Accepts a bare number of MiB, or the same
// number with an M / m / MiB suffix so the flag mimics the systemd spelling.
bool parse_memory_max_mb(const char* text, int& mb, std::string& error);

// systemd spellings. MemoryHigh is 85% of the ceiling so the kernel starts
// reclaiming (which only slows the newest session) before MemoryMax would kill
// the whole process (which drops every session).
std::string memory_max_systemd_value(int mb);
std::string memory_high_systemd_value(int mb);

// Bytes, for the relay budget.
std::size_t memory_max_bytes(int mb);

} // namespace bpb::util
