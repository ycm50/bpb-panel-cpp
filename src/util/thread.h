#pragma once
// Small-stack threads.
//
// Every proxied session spawns threads, and std::thread always asks for the
// platform default stack (8 MB of address space on Linux). A relay thread needs
// a few tens of KB, so with a hundred sessions the reservations alone crowd the
// address space and glibc hands each thread its own malloc arena. Both cost
// memory that shows up as RSS on a 469 MB VPS.
#include <cstddef>
#include <functional>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <pthread.h>
#endif

namespace bpb::util {

// Threads are created detached: the session owns nothing that a joiner could
// observe, and a finished session must not leave anything behind.
bool spawn_detached(std::function<void()> fn, std::size_t stack_bytes = 256 * 1024);

// Joinable variant for the two relay directions, which must both be finished
// before the session closes its resources.
class Thread {
public:
    Thread() = default;
    ~Thread();
    Thread(const Thread&) = delete;
    Thread& operator=(const Thread&) = delete;

    bool start(std::function<void()> fn, std::size_t stack_bytes = 128 * 1024);
    void join();
    bool joinable() const { return started_; }

private:
    bool started_ = false;
#ifdef _WIN32
    HANDLE handle_ = nullptr;
#else
    pthread_t tid_{};
#endif
};

// Returns heap pages that the allocator is holding but nobody is using.
//
// A relay allocates per session and frees it again; glibc keeps those pages in
// its arenas, so a process that has served 200 sessions sits well above its
// cold-start RSS even though every session is gone. Rate limited internally:
// calling it per session is fine, trimming per session is not.
void release_free_memory();

} // namespace bpb::util
