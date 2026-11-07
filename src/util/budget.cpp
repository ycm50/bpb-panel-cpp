#include "util/budget.h"

#include "util/log.h"
#include "util/memlimit.h"

#include <algorithm>
#include <atomic>
#include <new>

namespace bpb::util {

namespace {

std::atomic<int> g_max_active{40};
std::atomic<long long> g_initial_bytes{static_cast<long long>(50 * 1024)};
std::atomic<long long> g_pool_bytes{static_cast<long long>(8 * 1024 * 1024)};
std::atomic<long long> g_max_bytes{static_cast<long long>(400 * 1024)};

// Memory ceiling in bytes, 0 = unknown. Set from --mem-max / the compiled-in
// default before any session exists; configure_relay_budget() clamps the pool
// against it so the relay budget can never be larger than what the cgroup (and
// the installer) actually allow.
std::atomic<long long> g_memory_limit_bytes{0};

std::atomic<long long> g_pool_used{0};
std::atomic<int> g_active{0};
std::atomic<int> g_rejected{0};

// Reservations are compare-exchange loops on one counter, so a failed attempt
// leaves no trace. Staying over the pool is impossible by construction: the
// increment only commits when the new total still fits.
constexpr std::size_t kFloorBytes = 4096;

bool reserve_bytes(std::size_t bytes) {
    long long want = static_cast<long long>(bytes);
    if (want <= 0) return true;
    const long long limit = g_pool_bytes.load(std::memory_order_relaxed);
    long long used = g_pool_used.load(std::memory_order_relaxed);
    for (;;) {
        if (used + want > limit) return false;
        if (g_pool_used.compare_exchange_weak(used, used + want, std::memory_order_relaxed))
            return true;
    }
}

void unreserve_bytes(std::size_t bytes) {
    long long want = static_cast<long long>(bytes);
    if (want <= 0) return;
    g_pool_used.fetch_sub(want, std::memory_order_relaxed);
}

// A refused session is a capacity event, not a bug: log it, but at most once
// every few seconds so a flood cannot turn the journal into the bottleneck.
void note_rejection() {
    const int n = g_rejected.fetch_add(1, std::memory_order_relaxed) + 1;
    if (n % 100 == 1)
        bpb::log::warn("[relay] refused %d session(s): %d active, limit %d", n,
                       g_active.load(std::memory_order_relaxed),
                       g_max_active.load(std::memory_order_relaxed));
}

} // namespace

void configure_relay_budget(const RelayBudgetSettings& settings) {
    const int active = std::max(1, settings.max_active);
    const long long initial = static_cast<long long>(std::max<std::size_t>(4096, settings.initial_bytes));
    const long long max_bytes = static_cast<long long>(std::max<std::size_t>(settings.initial_bytes, settings.max_bytes));
    // A pool smaller than one full buffer would leave every stream stuck at the
    // initial size; clamp instead of silently disabling growth.
    long long pool = static_cast<long long>(std::max<std::size_t>(initial, settings.pool_bytes));
    // The pool must also fit inside the process's memory ceiling: it is the one
    // part of the footprint that scales with load on purpose. Without this the
    // relay could reserve more than the cgroup allows, the kernel would answer
    // with an OOM kill, and every live session would die at once -- the exact
    // failure this budget exists to prevent.
    if (g_memory_limit_bytes.load(std::memory_order_relaxed) > 0) {
        const long long ceiling = g_memory_limit_bytes.load(std::memory_order_relaxed);
        // Half the ceiling: the other half is the process's own heap, OpenSSL
        // state, lwIP and the TLS handshake spikes.
        const long long relay_ceiling = ceiling / 2;
        if (pool > relay_ceiling) {
            // configure_relay_budget runs several times during startup (the
            // ceiling from argv, then the settings, then the save that follows);
            // one line per distinct pair is enough to explain the clamp.
            static long long last_pool = -1;
            static long long last_ceiling = -1;
            if (pool != last_pool || ceiling != last_ceiling) {
                last_pool = pool;
                last_ceiling = ceiling;
                bpb::log::warn("[relay] pool %lld KiB exceeds half of the %lld KiB memory "
                               "ceiling; clamping",
                               pool / 1024, ceiling / 1024);
            }
            pool = std::max<long long>(initial, relay_ceiling);
        }
    }

    g_max_active.store(active, std::memory_order_relaxed);
    g_initial_bytes.store(initial, std::memory_order_relaxed);
    g_max_bytes.store(max_bytes, std::memory_order_relaxed);
    g_pool_bytes.store(pool, std::memory_order_relaxed);
}

RelayBudgetSettings relay_budget_settings() {
    RelayBudgetSettings s;
    s.max_active = g_max_active.load(std::memory_order_relaxed);
    s.initial_bytes = static_cast<std::size_t>(g_initial_bytes.load(std::memory_order_relaxed));
    s.pool_bytes = static_cast<std::size_t>(g_pool_bytes.load(std::memory_order_relaxed));
    s.max_bytes = static_cast<std::size_t>(g_max_bytes.load(std::memory_order_relaxed));
    return s;
}

void set_memory_limit(std::size_t bytes) {
    g_memory_limit_bytes.store(static_cast<long long>(bytes), std::memory_order_relaxed);
    // Re-apply the current settings so a ceiling set after configuration (the
    // normal order: the ceiling comes from argv, the rest from settings.json)
    // still clamps the pool.
    configure_relay_budget(relay_budget_settings());
}

std::size_t memory_limit_bytes() {
    return static_cast<std::size_t>(g_memory_limit_bytes.load(std::memory_order_relaxed));
}

std::size_t relay_buffer_initial_bytes() {
    const std::size_t initial = static_cast<std::size_t>(g_initial_bytes.load(std::memory_order_relaxed));
    // Under memory pressure the pool may already be exhausted by live sessions.
    // A new stream still has to run, so it halves the initial size instead of
    // being refused: slow is better than a refused tunnel.
    for (std::size_t want = initial; want >= 4096; want /= 2) {
        const std::size_t used = static_cast<std::size_t>(g_pool_used.load(std::memory_order_relaxed));
        const std::size_t limit = static_cast<std::size_t>(g_pool_bytes.load(std::memory_order_relaxed));
        if (used + want <= limit) return want;
    }
    return 4096;
}

int relay_active_sessions() { return g_active.load(std::memory_order_relaxed); }
int relay_rejected_sessions() { return g_rejected.load(std::memory_order_relaxed); }
std::size_t relay_pool_used() {
    return static_cast<std::size_t>(g_pool_used.load(std::memory_order_relaxed));
}
std::size_t relay_pool_limit() {
    return static_cast<std::size_t>(g_pool_bytes.load(std::memory_order_relaxed));
}

SessionPermit::~SessionPermit() {
    if (admitted_) {
        admitted_ = false;
        g_active.fetch_sub(1, std::memory_order_relaxed);
    }
}

std::shared_ptr<SessionPermit> SessionPermit::try_acquire() {
    const int limit = g_max_active.load(std::memory_order_relaxed);
    int cur = g_active.load(std::memory_order_relaxed);
    for (;;) {
        if (cur >= limit) {
            note_rejection();
            return nullptr;
        }
        if (g_active.compare_exchange_weak(cur, cur + 1, std::memory_order_relaxed)) break;
    }
    auto permit = std::make_shared<SessionPermit>();
    permit->admitted_ = true;
    return permit;
}

RelayBuffer::RelayBuffer(std::size_t initial) {
    std::size_t want = initial ? initial : relay_buffer_initial_bytes();
    // The pool is a ceiling, not a promise. When even the smallest buffer does
    // not fit, the session still runs at that smallest size rather than being
    // refused: a slow tunnel beats no tunnel. The overflow is bounded by
    // kFloorBytes per live session, so the pool can be exceeded by at most
    // kFloorBytes * max_active and never grows with connection duration.
    if (!reserve_bytes(want)) {
        want = kFloorBytes;
        reserved_ = reserve_bytes(want) ? want : 0;
    } else {
        reserved_ = want;
    }
    char* raw = new (std::nothrow) char[want];
    if (!raw) {
        unreserve_bytes(reserved_);
        reserved_ = 0;
        want = 0;
    }
    data_.reset(raw);
    capacity_ = want;
}

RelayBuffer::~RelayBuffer() { unreserve_bytes(reserved_); }

bool RelayBuffer::grow() {
    const std::size_t max_bytes = static_cast<std::size_t>(g_max_bytes.load(std::memory_order_relaxed));
    if (capacity_ >= max_bytes) return false;
    std::size_t next = capacity_ * 2;
    if (next > max_bytes) next = max_bytes;
    const std::size_t extra = next - capacity_;
    if (!reserve_bytes(extra)) return false;
    // No copy: every caller grows right after the bytes it just read have been
    // forwarded, so the old contents are dead. Copying would memcpy up to
    // kMaxBytes for nothing and briefly double the reservation.
    std::unique_ptr<char[]> bigger(new (std::nothrow) char[next]);
    if (!bigger) {
        unreserve_bytes(extra);
        return false;
    }
    data_ = std::move(bigger);
    capacity_ = next;
    reserved_ += extra;
    return true;
}

} // namespace bpb::util