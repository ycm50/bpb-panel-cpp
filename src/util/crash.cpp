#include "util/crash.h"

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
// Windows builds use the same code path only for the log switch; there is no
// backtrace() there and no systemd to swallow the crash, so keep it empty.
namespace bpb {
void install_crash_handler() {}
} // namespace bpb
#else
#include <unistd.h>

// backtrace(3) lives in glibc, not in POSIX: musl (Alpine, the distro the CI
// static binaries are built in) ships no <execinfo.h> and no libexecinfo, so a
// hard #include breaks every Linux build. The frames are a debugging nicety --
// "which signal killed us" is the part that matters -- so detect the header and
// degrade to a backtrace-less handler when it is missing.
#if defined(__has_include)
#  if __has_include(<execinfo.h>)
#    define BPB_HAVE_EXECINFO 1
#  endif
#endif
#ifdef BPB_HAVE_EXECINFO
#  include <execinfo.h>
#endif

namespace bpb {
namespace {

#ifdef BPB_HAVE_EXECINFO
constexpr int kMaxFrames = 40;
#endif

void write_str(int fd, const char* s) {
    if (!s) return;
    ssize_t ignored = ::write(fd, s, std::strlen(s));
    (void)ignored;
}

void write_int(int fd, long v) {
    char buf[24];
    int i = 0;
    if (v == 0) {
        buf[i++] = '0';
    } else {
        char tmp[24];
        int j = 0;
        const bool neg = v < 0;
        unsigned long u = neg ? static_cast<unsigned long>(-v) : static_cast<unsigned long>(v);
        while (u && j < 24) {
            tmp[j++] = static_cast<char>('0' + (u % 10));
            u /= 10;
        }
        if (neg) buf[i++] = '-';
        while (j) buf[i++] = tmp[--j];
    }
    buf[i] = 0;
    write_str(fd, buf);
}

void handler(int sig) {
    write_str(2, "\n[bpb] fatal signal ");
    write_int(2, sig);
#ifdef BPB_HAVE_EXECINFO
    // backtrace() allocates on the first call; call it once from handler code
    // that runs before the heap is known to be sane is a risk, but a corrupted
    // heap plus a dying process makes that acceptable -- it is this or nothing.
    void* frames[kMaxFrames];
    const int n = ::backtrace(frames, kMaxFrames);
    write_str(2, " -- backtrace:\n");
    ::backtrace_symbols_fd(frames, n, 2);
    write_str(2, "[bpb] end backtrace\n");
#else
    write_str(2, " -- no backtrace support in this libc\n");
#endif
    ::signal(sig, SIG_DFL);
    ::raise(sig);
}

} // namespace

void install_crash_handler() {
    const int sigs[] = {SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE};
    for (int sig : sigs) {
        ::signal(sig, handler);
    }
#ifdef SIGPIPE
    // A peer that disappears mid-write must not take the process down: on Linux
    // write() on a half-closed socket raises SIGPIPE, whose default action is
    // termination. Every relay path already treats a failed write as "this
    // connection is over", so the signal is simply ignored.
    ::signal(SIGPIPE, SIG_IGN);
#endif
}

} // namespace bpb
#endif
