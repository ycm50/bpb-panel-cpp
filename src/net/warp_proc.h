#pragma once
#include "net/net.h"
#include "settings/store.h"

#include <string>

namespace bpb::net {

// The WARP outbound is delegated to an external, supervised `warp-rust`
// process (third_party/cf-warp-rust). It owns the WireGuard/Noise session, the
// userspace TCP/IP stack and the WARP account; bpb only generates its config,
// keeps it alive and dials through the SOCKS5 port it exposes.
//
// Why a separate process instead of the old in-tree WireGuard stack:
//   * the account lifecycle (register once, reuse data/account.json, rotate
//     identities, refresh config every 24h) is exactly what warp-rust already
//     implements, and re-implementing it invites duplicate registrations;
//   * a crash or a wedged netstack cannot take the panel down with it.
// bpb NEVER registers: warp-rust only registers when data/account.json is
// missing, and we always point it at a persistent directory.

// Locates the warp-rust executable. Order: explicit "binary" setting, then a
// sibling of the running bpb executable, then ./warp-rust, then $PATH.
std::string warp_find_binary(const std::string& configured);

// Renders config.toml for the external process. Returns false and fills *error
// when the settings are unusable (bad port, missing data dir, ...).
bool warp_write_config(const Store& store, const std::string& path, std::string& error);

// Starts the external process and waits until its SOCKS5 port accepts
// connections. Returns false with a reason when disabled or unusable.
bool warp_proc_start(Store& store, std::string& error);

// True once the SOCKS5 listener accepts connections.
bool warp_proc_ready();

// "stopped" | "starting" | "ready (pid ...)" | "restarting" | "failed: ..."
std::string warp_proc_status();

// Terminates the child process and stops the supervisor.
void warp_proc_stop();

// SOCKS5 endpoint published by the external process.
std::string warp_proc_socks_host();
int warp_proc_socks_port();

// Opens a SOCKS5 CONNECT tunnel to host:port through the local WARP process.
// Returns a connected non-blocking socket, or net::kInvalid on failure.
socket_t warp_socks_connect(const std::string& host, int port, int timeout_ms);

} // namespace bpb::net
