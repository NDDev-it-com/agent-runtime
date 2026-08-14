// SPDX-License-Identifier: AGPL-3.0-only

package agentruntime

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// terminationWorkspace returns a workspace with the instruction file the shared
// helper-process manifest expects.
func terminationWorkspace(t *testing.T) Workspace {
	t.Helper()
	root := t.TempDir()
	writeTestFile(t, root, "instructions.md", "x")
	w, err := OpenWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestCallerDeadlineIsNotAttributedToTheTask(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	m := testManifest(os.Args[0], "sleep")
	m.Timeout = Duration{time.Hour}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	result, err := (Runner{Workspace: terminationWorkspace(t)}).Run(ctx, m)
	if result.TimedOut {
		t.Fatalf("caller deadline reported as a Task timeout: %v", err)
	}
	if !result.Cancelled {
		t.Fatalf("caller deadline was not attributed to the caller: result=%#v err=%v", result, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("caller deadline cause was lost: %v", err)
	}
	if strings.Contains(err.Error(), m.Timeout.String()) {
		t.Fatalf("error claims the manifest timeout elapsed: %v", err)
	}
}

func TestCallerCancellationIsTyped(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	m := testManifest(os.Args[0], "sleep")
	m.Timeout = Duration{time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	defer cancel()
	result, err := (Runner{Workspace: terminationWorkspace(t)}).Run(ctx, m)
	if result.TimedOut || !result.Cancelled {
		t.Fatalf("cancellation misattributed: result=%#v err=%v", result, err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation cause was lost behind the process error: %v", err)
	}
}

func TestManifestTimeoutIsAttributedToTheTask(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	m := testManifest(os.Args[0], "sleep")
	m.Timeout = Duration{20 * time.Millisecond}
	result, err := (Runner{Workspace: terminationWorkspace(t)}).Run(context.Background(), m)
	if !result.TimedOut || result.Cancelled {
		t.Fatalf("manifest timeout misattributed: result=%#v err=%v", result, err)
	}
	if !strings.Contains(err.Error(), "exceeded its 20ms timeout") {
		t.Fatalf("error does not name the manifest timeout: %v", err)
	}
}

func TestSuccessfulRunIsNeitherTimedOutNorCancelled(t *testing.T) {
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	result, err := (Runner{Workspace: terminationWorkspace(t)}).Run(context.Background(), testManifest(os.Args[0], "echo"))
	if err != nil {
		t.Fatal(err)
	}
	if result.TimedOut || result.Cancelled || !result.Accepted {
		t.Fatalf("result=%#v", result)
	}
}
