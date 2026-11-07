#pragma once
// Relay memory budget: admission control plus a shared pool for relay buffers.
//
// Every proxied session costs two threads, one file-descriptor pair, a TLS
// session and a pair of relay buffers. None of that is large on its own, but a
// burst of connections multiplies the per-session cost, and on a small VPS the
// kernel answers the overshoot with the OOM killer, which drops every session
// instead of the newest one. This module gives the data path two ceilings:
//
//   * active sessions  -- acquired BEFORE a session allocates its threads and
//                         buffers, so an over-capacity connection is refused
//                         while it still costs nothing;
//   * relay bytes      -- a process-wide pool that relay buffers reserve from.
//                         A buffer starts small and only widens while the pool
//                         can pay for it, so a few high-throughput streams can
//                         still grow to a full bandwidth-delay window while a
//                         crowd cannot.
//
// Both ceilings are advisory accounting, not allocations: going over is refused
// rather than allowed to fail later, and the numbers are reported so the panel
// and the tests can see which ceiling was hit.
#include <cstddef>
#include <memory>

namespace bpb::util {

struct RelayBudgetSettings {
    // Sessions allowed to hold relay resources at the same time.
    int max_active = 40;
    // Bytes a relay buffer starts with. Small enough that forty sessions fit in
    // a few MB, large enough to keep a normal download streaming without growth.
    std::size_t initial_bytes = 50 * 1024;
    // Total bytes all relay buffers may hold together, growth included.
    std::size_t pool_bytes = 8 * 1024 * 1024;
    // Largest a single relay buffer may grow to.
    std::size_t max_bytes = 400 * 1024;
};

// Applies the settings. Safe to call at any time; already-allocated buffers keep
// their capacity, they are just measured against the new pool from then on.
void configure_relay_budget(const RelayBudgetSettings& settings);
RelayBudgetSettings relay_budget_settings();

// The process memory ceiling, in bytes (0 = unknown). Two consumers: the relay
// pool is clamped to half of it so the budget can never reserve more than the
// cgroup allows, and the panel reports it so an operator can see the number the
// kernel will actually enforce.
//
// Safe to call before or after configure_relay_budget(): setting the ceiling
// re-applies the current settings.
void set_memory_limit(std::size_t bytes);
std::size_t memory_limit_bytes();

// Bytes a new relay buffer may start with once the pool is taken into account.
std::size_t relay_buffer_initial_bytes();

// Live counters, for the panel and the tests.
int relay_active_sessions();
int relay_rejected_sessions();
std::size_t relay_pool_used();
std::size_t relay_pool_limit();

// RAII permit for one active session. Acquire it on the accepting thread and
// move/capture it into the session thread: the permit then lives exactly as long
// as the relay does, and the count cannot drift if a session throws.
class SessionPermit {
public:
    SessionPermit() = default;
    ~SessionPermit();
    SessionPermit(const SessionPermit&) = delete;
    SessionPermit& operator=(const SessionPermit&) = delete;

    // Tries to take a slot. A failed permit leaves the session unadmitted; the
    // caller must refuse the connection instead of running it uncounted.
    static std::shared_ptr<SessionPermit> try_acquire();

    bool admitted() const { return admitted_; }

private:
    bool admitted_ = false;
};

// One direction's relay buffer.
//
// The buffer grows only between reads, never while a pointer into it is in use,
// and only when the previous read filled it completely -- that is the moment
// where a larger window can actually raise throughput. A buffer that keeps
// arriving half empty is already keeping up and is left alone.
class RelayBuffer {
public:
    explicit RelayBuffer(std::size_t initial = 0);
    ~RelayBuffer();
    RelayBuffer(const RelayBuffer&) = delete;
    RelayBuffer& operator=(const RelayBuffer&) = delete;

    char* data() { return data_.get(); }
    std::size_t size() const { return capacity_; }

    // Doubles the buffer when the pool can pay for the larger reservation.
    // Returns true when it grew.
    bool grow();

private:
    std::unique_ptr<char[]> data_;
    std::size_t capacity_ = 0;
    std::size_t reserved_ = 0;
};

} // namespace bpb::util