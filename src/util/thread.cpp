#include "util/thread.h"

#include "util/log.h"

#include <atomic>
#include <chrono>
#include <cstdint>

#if defined(__linux__) && defined(__GLIBC__)
#include <malloc.h>
#endif

namespace bpb::util {

namespace {

#ifdef _WIN32
unsigned __stdcall trampoline(void* arg) {
    auto* fn = static_cast<std::function<void()>*>(arg);
    (*fn)();
    delete fn;
    return 0;
}
#else
void* trampoline(void* arg) {
    auto* fn = static_cast<std::function<void()>*>(arg);
    (*fn)();
    delete fn;
    return nullptr;
}
#endif

std::size_t clamp_stack(std::size_t want) {
    if (want < 64 * 1024) return 64 * 1024;
    return want;
}

} // namespace

bool spawn_detached(std::function<void()> fn, std::size_t stack_bytes) {
    auto* holder = new std::function<void()>(std::move(fn));
#ifdef _WIN32
    uintptr_t handle = _beginthreadex(nullptr, static_cast<unsigned>(clamp_stack(stack_bytes)),
                                      trampoline, holder, 0, nullptr);
    if (!handle) {
        delete holder;
        return false;
    }
    CloseHandle(reinterpret_cast<HANDLE>(handle));
    return true;
#else
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0) {
        delete holder;
        return false;
    }
    pthread_attr_setstacksize(&attr, clamp_stack(stack_bytes));
    pthread_t tid;
    const int rc = pthread_create(&tid, &attr, trampoline, holder);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        delete holder;
        bpb::log::error("spawn_detached: pthread_create failed (%d)", rc);
        return false;
    }
    pthread_detach(tid);
    return true;
#endif
}

Thread::~Thread() { join(); }

bool Thread::start(std::function<void()> fn, std::size_t stack_bytes) {
    if (started_) return false;
    auto* holder = new std::function<void()>(std::move(fn));
#ifdef _WIN32
    const uintptr_t handle =
        _beginthreadex(nullptr, static_cast<unsigned>(clamp_stack(stack_bytes)), trampoline, holder, 0,
                       nullptr);
    if (!handle) {
        delete holder;
        return false;
    }
    handle_ = reinterpret_cast<HANDLE>(handle);
    started_ = true;
    return true;
#else
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0) {
        delete holder;
        return false;
    }
    pthread_attr_setstacksize(&attr, clamp_stack(stack_bytes));
    const int rc = pthread_create(&tid_, &attr, trampoline, holder);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        delete holder;
        bpb::log::error("Thread::start: pthread_create failed (%d)", rc);
        return false;
    }
    started_ = true;
    return true;
#endif
}

void Thread::join() {
    if (!started_) return;
    started_ = false;
#ifdef _WIN32
    if (handle_) {
        WaitForSingleObject(handle_, INFINITE);
        CloseHandle(handle_);
        handle_ = nullptr;
    }
#else
    pthread_join(tid_, nullptr);
#endif
}

void release_free_memory() {
#if defined(__linux__) && defined(__GLIBC__)
    // Trimming walks every arena, so it must not run once per session under
    // load. Once every few seconds is enough to keep the resident set of an
    // idle relay at its cold-start level.
    static std::atomic<std::int64_t> last{0};
    const std::int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now().time_since_epoch())
                                 .count();
    std::int64_t seen = last.load(std::memory_order_relaxed);
    if (now - seen < 5000) return;
    if (!last.compare_exchange_strong(seen, now)) return;
    malloc_trim(0);
#endif
}

} // namespace bpb::util
