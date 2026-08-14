// SPDX-License-Identifier: AGPL-3.0-only

//go:build !darwin && !linux

package agentruntime

import "os/exec"

// The supported platforms are Linux and macOS. Elsewhere the runtime keeps the
// standard library's behaviour — the direct child is terminated and its
// descendants are not owned — rather than pretending to a guarantee it has no
// mechanism for. SECURITY.md states this boundary.
func ownProcessGroup(*exec.Cmd) {}

func terminateProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
