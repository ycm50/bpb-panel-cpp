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

# --- bpb ---------------------------------------------------------------------
file(GLOB_RECURSE BPB_SOURCES CONFIGURE_DEPENDS src/*.cpp)
list(APPEND BPB_SOURCES third_party/qrcodegen.cpp)

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
target_link_libraries(bpb PRIVATE OpenSSL::SSL OpenSSL::Crypto ZLIB::ZLIB)

if(WIN32)
  target_link_libraries(bpb PRIVATE ws2_32)
  target_compile_definitions(bpb PRIVATE _WIN32_WINNT=0x0601 NOMINMAX WIN32_LEAN_AND_MEAN)
  target_link_options(bpb PRIVATE -static-libgcc -static-libstdc++ -Wl,--gc-sections)
else()
  target_link_libraries(bpb PRIVATE pthread)
  target_link_options(bpb PRIVATE -static-libgcc -static-libstdc++ -Wl,--gc-sections)
  if(BPB_STATIC)
    target_link_options(bpb PRIVATE -static)
  endif()
endif()

install(TARGETS bpb RUNTIME DESTINATION bin)
