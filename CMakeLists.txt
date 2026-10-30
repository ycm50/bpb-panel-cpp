cmake_minimum_required(VERSION 3.20)
project(bpb_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# MSVC is not supported: use MinGW-w64 (UCRT64), GCC or Clang.
if(MSVC)
  message(FATAL_ERROR "MSVC is not allowed. Use MinGW-w64 (UCRT64) or GCC.")
endif()

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

set(CMAKE_CXX_FLAGS_RELEASE "-O2 -ffunction-sections -fdata-sections")

file(GLOB_RECURSE BPB_SOURCES CONFIGURE_DEPENDS src/*.cpp)
list(APPEND BPB_SOURCES third_party/qrcodegen.cpp)

add_executable(bpb ${BPB_SOURCES})
target_include_directories(bpb PRIVATE src)
target_include_directories(bpb SYSTEM PRIVATE third_party)
target_link_libraries(bpb PRIVATE OpenSSL::SSL OpenSSL::Crypto ZLIB::ZLIB)

if(WIN32)
  target_link_libraries(bpb PRIVATE ws2_32)
  target_compile_definitions(bpb PRIVATE _WIN32_WINNT=0x0601 NOMINMAX WIN32_LEAN_AND_MEAN)
  target_link_options(bpb PRIVATE -static-libgcc -static-libstdc++ -Wl,--gc-sections)
else()
  target_link_libraries(bpb PRIVATE pthread)
  target_link_options(bpb PRIVATE -static-libgcc -static-libstdc++ -Wl,--gc-sections)
endif()

install(TARGETS bpb RUNTIME DESTINATION bin)
