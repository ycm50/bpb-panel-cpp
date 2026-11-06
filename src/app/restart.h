#pragma once
#include <string>

namespace bpb::app {

// bpb --res [pid]
//
// Restarts a running bpb without needing the operator to know how it was
// started:
//
//   bpb --res <pid>   restart that exact process
//   bpb --res         restart the bpb with the LOWEST pid on this machine
//
// "Restart" means different things depending on who owns the process, and the
// difference matters:
//
//   * started by systemd  -> `systemctl restart <unit>`, so the unit's own
//     Restart= policy, environment and cgroup stay in charge. Killing the pid
//     and hoping the supervisor notices would lose all of that.
//   * started by hand     -> terminate it and re-exec the same argv in the same
//     working directory with the same environment.
//
// Returns 0 on success, 1 on failure (nothing to restart, permission denied,
// the target refused to die, ...). Diagnostics go to stderr.
int restart_bpb(const std::string& pid_arg);

} // namespace bpb::app
