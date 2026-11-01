cmake_minimum_required(VERSION 3.20)
project(bpb_native LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# MSVC is not supported: use MinGW-w64 (UCRT64), GCC or Clang.
if(MSVC)
  message(FATAL_ERROR "MSVC is not allowed. Use MinGW-w64 (UCRT64) or GCC.")
endif()

# Optional fully-static build (used by CI to ship portable Linux binaries).
# When BPB_STATIC=ON we force CMake to resolve the *.a archives: setting
# CMAKE_EXE_LINKER_FLAGS=-static alone still links against libssl.so and the
# link then fails with "attempted static link of dynamic object".
option(BPB_STATIC "Link everything statically" OFF)
if(BPB_STATIC)
  set(OPENSSL_USE_STATIC_LIBS ON)
  set(ZLIB_USE_STATIC_LIBS ON)
endif()

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

set(CMAKE_CXX_FLAGS_RELEASE "-O2 -ffunction-sections -fdata-sections")
set(CMAKE_C_FLAGS_RELEASE "-O2 -ffunction-sections -fdata-sections")

# --- vendored lwIP (userspace TCP/IP stack for the WireGuard outbound) -------
set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwip)
set(LWIP_SOURCES
  ${LWIP_DIR}/src/core/def.c
  ${LWIP_DIR}/src/core/dns.c
  ${LWIP_DIR}/src/core/inet_chksum.c
  ${LWIP_DIR}/src/core/init.c
  ${LWIP_DIR}/src/core/ip.c
  ${LWIP_DIR}/src/core/mem.c
  ${LWIP_DIR}/src/core/memp.c
  ${LWIP_DIR}/src/core/netif.c
  ${LWIP_DIR}/src/core/pbuf.c
  ${LWIP_DIR}/src/core/raw.c
  ${LWIP_DIR}/src/core/stats.c
  ${LWIP_DIR}/src/core/sys.c
  ${LWIP_DIR}/src/core/tcp.c
  ${LWIP_DIR}/src/core/tcp_in.c
  ${LWIP_DIR}/src/core/tcp_out.c
  ${LWIP_DIR}/src/core/timeouts.c
  ${LWIP_DIR}/src/core/udp.c
  ${LWIP_DIR}/src/core/ipv4/acd.c
  ${LWIP_DIR}/src/core/ipv4/etharp.c
  ${LWIP_DIR}/src/core/ipv4/icmp.c
  ${LWIP_DIR}/src/core/ipv4/ip4.c
  ${LWIP_DIR}/src/core/ipv4/ip4_addr.c
  ${LWIP_DIR}/src/core/ipv4/ip4_frag.c
)

add_library(lwip STATIC ${LWIP_SOURCES})
target_include_directories(lwip PUBLIC
  ${LWIP_DIR}/src/include
  ${LWIP_DIR}
)
target_compile_definitions(lwip PRIVATE LWIP_NO_UNISTD_H=1)

# --- inbound protocols -------------------------------------------------------
# Every inbound protocol lives in its own file under src/inbound/proto/ and is
# compiled ONLY when it is selected here, so a binary built with -DBPB_INBOUNDS=
# vless does not contain -- and does not even compile -- the other protocols.
#
# What the binary was built with is exposed to the code as BPB_HAVE_<PROTO>; the
# dispatcher, the panel and the subscription generators consult
# bpb::inbound::all() instead of hard-coding protocol names.
#
# Add a protocol: write src/inbound/proto/<name>_ws.cpp defining
# <name>_inbound, then append the name to BPB_ALL_INBOUNDS below.
set(BPB_ALL_INBOUNDS vless trojan shadowsocks vmess)
set(BPB_INBOUNDS "vless" CACHE STRING
    "Inbound protocols to compile: comma separated, or 'all' for every implemented one")

if(BPB_INBOUNDS STREQUAL "all")
  set(BPB_INBOUND_SELECTED ${BPB_ALL_INBOUNDS})
else()
  string(REPLACE "," ";" BPB_INBOUND_SELECTED "${BPB_INBOUNDS}")
endif()
if(NOT BPB_INBOUND_SELECTED)
  message(FATAL_ERROR "BPB_INBOUNDS is empty: choose at least one of ${BPB_ALL_INBOUNDS}")
endif()

set(BPB_INBOUND_SOURCES "")
foreach(proto IN LISTS BPB_INBOUND_SELECTED)
  string(STRIP "${proto}" proto)
  string(TOLOWER "${proto}" proto)
  if(NOT proto IN_LIST BPB_ALL_INBOUNDS)
    message(FATAL_ERROR "unknown inbound '${proto}'; implemented: ${BPB_ALL_INBOUNDS}")
  endif()
  list(APPEND BPB_INBOUND_SOURCES src/inbound/proto/${proto}_ws.cpp)
  string(TOUPPER "${proto}" proto_upper)
  add_compile_definitions(BPB_HAVE_${proto_upper}=1)
endforeach()
list(REMOVE_DUPLICATES BPB_INBOUND_SOURCES)
message(STATUS "bpb inbounds: ${BPB_INBOUND_SELECTED}")

# --- bpb ---------------------------------------------------------------------
file(GLOB_RECURSE BPB_SOURCES CONFIGURE_DEPENDS src/*.cpp)
list(APPEND BPB_SOURCES third_party/qrcodegen.cpp)
# The per-protocol files are added explicitly above; globbing them would compile
# protocols this build was asked to leave out.
list(FILTER BPB_SOURCES EXCLUDE REGEX "/src/inbound/proto/")
list(APPEND BPB_SOURCES ${BPB_INBOUND_SOURCES})

# The Cloudflare Tunnel client is a POSIX implementation (poll(2), <arpa/inet.h>,
# <sys/socket.h>, stream sockets as ints). Shipping it on Windows would mean a
# second backend for the same protocol, so Windows builds simply leave it out:
# the panel keeps working, only the built-in tunnel is unavailable there.
if(WIN32)
  list(FILTER BPB_SOURCES EXCLUDE REGEX "/src/tunnel/")
  list(APPEND BPB_SOURCES platform/tunnel_stub.cpp)
endif()

add_executable(bpb ${BPB_SOURCES})
target_include_directories(bpb PRIVATE src platform)
target_include_directories(bpb SYSTEM PRIVATE third_party)
target_link_libraries(bpb PRIVATE OpenSSL::SSL OpenSSL::Crypto ZLIB::ZLIB lwip)

if(WIN32)
  target_link_libraries(bpb PRIVATE ws2_32)
  target_compile_definitions(bpb PRIVATE _WIN32_WINNT=0x0601 NOMINMAX WIN32_LEAN_AND_MEAN)
  target_link_options(bpb PRIVATE -static-libgcc -static-libstdc++ -Wl,--gc-sections)
else()
  target_link_libraries(bpb PRIVATE pthread)
  # -rdynamic keeps the symbol table so the crash handler's backtrace prints
  # function names instead of bare addresses.
  target_link_options(bpb PRIVATE -static-libgcc -static-libstdc++ -Wl,--gc-sections -rdynamic)
  if(BPB_STATIC)
    target_link_options(bpb PRIVATE -static)
  endif()
endif()

install(TARGETS bpb RUNTIME DESTINATION bin)
