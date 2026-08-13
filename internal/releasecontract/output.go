// SPDX-License-Identifier: AGPL-3.0-only

package releasecontract

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// OutputFailure classifies a fail-closed release output transaction failure.
type OutputFailure string

const (
	OutputInvalidParent     OutputFailure = "invalid_parent"
	OutputDestinationExists OutputFailure = "destination_exists"
	OutputIdentityChanged   OutputFailure = "identity_changed"
	OutputPartial           OutputFailure = "partial_transaction"
	OutputCleanup           OutputFailure = "cleanup_failure"
)

// OutputError preserves the root filesystem error while exposing the release
// transaction stage to callers without requiring string matching.
type OutputError struct {
	Kind      OutputFailure
	Operation string
	Err       error
}

func (e *OutputError) Error() string {
	return fmt.Sprintf("release output %s during %s: %v", e.Kind, e.Operation, e.Err)
}

func (e *OutputError) Unwrap() error { return e.Err }

func outputError(kind OutputFailure, operation string, err error) error {
	if err == nil {
		return nil
	}
	return &OutputError{Kind: kind, Operation: operation, Err: err}
}

// CanonicalOutputPath joins one absent portable leaf to an absolute host root.
// Filesystem identity and alias policy remain enforced by the fd-anchored
// publication transaction when the returned path is used.
func CanonicalOutputPath(root, leaf string) (string, error) {
	if root == "" || !filepath.IsAbs(root) {
		return "", errors.New("output root must be absolute")
	}
	cleanRoot := filepath.Clean(root)
	if cleanRoot == "." || cleanRoot == "" {
		return "", errors.New("output root is empty")
	}
	if leaf == "" || leaf == "." || leaf == ".." || filepath.Base(leaf) != leaf || strings.ContainsAny(leaf, `/\\`) {
		return "", errors.New("output leaf must be one portable basename")
	}
	joined := filepath.Join(cleanRoot, leaf)
	if filepath.Dir(joined) != cleanRoot || filepath.Base(joined) != leaf {
		return "", errors.New("output path escaped canonical root")
	}
	return joined, nil
}
