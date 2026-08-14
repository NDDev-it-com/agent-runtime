// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package agentruntime

import (
	"os/exec"
	"syscall"
)

// ownProcessGroup places the child in a new process group so the runtime can
// terminate what the Task started rather than only the process it launched.
//
// exec.CommandContext kills the direct child alone. A command that spawns
// anything — a shell backgrounding work, a build driver, a supervisor — left
// those descendants running after the Runner had already returned a terminal
// timeout and observability had recorded the Task as over. Reproduced: a
// grandchild wrote into the workspace 2.7 seconds after a 300 ms timeout
// returned.
//
// This is bounded ownership, not a sandbox. A process that leaves the group
// deliberately is out of reach, and this module does not claim otherwise.
func ownProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// terminateProcessGroup signals the whole group. The negated process ID is the
// POSIX spelling for "the group led by this process"; the leader is the child
// itself because ownProcessGroup made it one.
//
// It falls back to the single process when the group cannot be addressed, which
// happens if the child has already been reaped, so cancellation never becomes a
// no-op just because the group is gone.
func terminateProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	pid := cmd.Process.Pid
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		return cmd.Process.Kill()
	}
	return nil
}
