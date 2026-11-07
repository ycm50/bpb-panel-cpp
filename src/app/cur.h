#pragma once
#include <string>

namespace bpb::app {

// bpb --cur
//
// Prints the Cloudflare Tunnel domain of every bpb instance that is already
// running on this machine, so an operator can find "the public address of the
// process that is up right now" without guessing which data directory belongs
// to which pid.
//
// data_override: --data given on the command line. When set, only that data
// directory is inspected (Windows builds cannot read another process's command
// line, so this is how they are pointed at an instance).
// Returns 0 when at least one instance was found, 1 otherwise.
// port_override: --port given next to --data, so a single instance can be
// inspected without /proc (0 keeps the 8080 default used by main()).
int print_current_tunnels(const std::string& data_override, int port_override = 0);

} // namespace bpb::app
