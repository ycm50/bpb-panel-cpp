#include "lwip/opt.h"
#include "lwip/sys.h"

#include <chrono>

extern "C" u32_t sys_now(void) {
    using namespace std::chrono;
    static const auto start = steady_clock::now();
    return static_cast<u32_t>(
        duration_cast<milliseconds>(steady_clock::now() - start).count());
}
