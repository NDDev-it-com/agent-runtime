// SPDX-License-Identifier: AGPL-3.0-only

package governance

import (
	"errors"
	"fmt"
	"slices"

	"github.com/NDDev-it-com/agent-runtime/internal/actions"
)

// VerifyCIWorkflow proves the workflow actually produces the check-runs the
// branch requires. A required context is a name the branch waits for, so the
// job that emits it must exist, must run, must run for every event the branch
// gates on, and must not rename itself out from under the requirement.
func VerifyCIWorkflow(contract Contract, workflow []byte) error {
	if err := contract.Validate(); err != nil {
		return err
	}
	w, err := actions.Parse(workflow)
	if err != nil {
		return err
	}
	pullRequest := w.Triggers["pull_request"]
	if !pullRequest.Present {
		return errors.New("CI workflow must run for every pull_request")
	}
	push := w.Triggers["push"]
	if !push.Present || !slices.Equal(push.Branches, []string{"main"}) {
		return errors.New("CI workflow must run on every push to main")
	}
	// A path filter turns a required check into one that never reports on the
	// changes it skipped, which leaves the branch waiting forever or, worse,
	// merging on a check that never examined the diff.
	for name, trigger := range map[string]actions.Trigger{"pull_request": pullRequest, "push": push} {
		if len(trigger.Paths) != 0 || len(trigger.PathsIgnore) != 0 {
			return fmt.Errorf("CI workflow %s trigger must not use path filters", name)
		}
	}
	for _, check := range contract.RequiredChecks {
		if check.Producer.Kind != "workflow" {
			continue
		}
		job, err := w.Job(check.Producer.Job)
		if err != nil {
			return fmt.Errorf("required check %q: %w", check.Context, err)
		}
		// GitHub names the check-run after the job's `name` when one is set, so
		// an override silently detaches the run from the required context.
		if job.NameSet {
			return fmt.Errorf("required job %q must not override its stable check name", check.Producer.Job)
		}
		if check.Producer.MatrixOS == "" {
			if check.Context != check.Producer.Job {
				return fmt.Errorf("required check %q does not equal job %q", check.Context, check.Producer.Job)
			}
			continue
		}
		if check.Context != check.Producer.Job+" ("+check.Producer.MatrixOS+")" {
			return fmt.Errorf("required matrix context %q is not canonical", check.Context)
		}
		// The context name carries the matrix value, so the lane that produces
		// it must still be declared. Dropping a lane retires a required check
		// without touching the branch.
		if !slices.Contains(job.Matrix["os"], check.Producer.MatrixOS) {
			return fmt.Errorf("required check %q needs matrix lane os=%s, which job %q does not declare", check.Context, check.Producer.MatrixOS, check.Producer.Job)
		}
	}
	return nil
}
