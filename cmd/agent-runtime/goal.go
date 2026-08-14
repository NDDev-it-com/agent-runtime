// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	goalpkg "github.com/NDDev-it-com/agent-runtime/goal"
)

const defaultJournalPath = ".agent-runtime/goal.json"

type stringsFlag []string

func (f *stringsFlag) String() string         { return strings.Join(*f, ",") }
func (f *stringsFlag) Set(value string) error { *f = append(*f, value); return nil }

func goalCommand(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: agent-runtime goal <init|status|add|evidence|check|advance>")
	}
	switch args[0] {
	case "init":
		return goalInit(args[1:], stdout, stderr)
	case "status":
		return goalStatus(args[1:], stdout, stderr)
	case "check":
		return goalCheck(args[1:], stdout, stderr)
	case "add":
		return goalAdd(args[1:], stdout, stderr)
	case "evidence":
		return goalEvidence(args[1:], stdout, stderr)
	case "advance":
		return goalAdvance(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown goal command %q", args[0])
	}
}

// goalFlags starts every goal command from the same journal flag, so read and
// mutation commands share one shape instead of parsing at different times.
func goalFlags(name string, stderr io.Writer) (*flag.FlagSet, *string) {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(stderr)
	return set, set.String("journal", defaultJournalPath, "durable goal journal path")
}

func revisionFlag(set *flag.FlagSet) *uint64 {
	return set.Uint64("revision", 0, "required expected journal revision")
}

func parseGoalFlags(set *flag.FlagSet, args []string, revision *uint64) error {
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if revision != nil && *revision == 0 {
		return errors.New("--revision must be positive")
	}
	return nil
}

func goalInit(args []string, stdout, stderr io.Writer) error {
	set, journalPath := goalFlags("goal init", stderr)
	id := set.String("id", "", "stable goal identifier")
	intent := set.String("intent", "", "desired outcome")
	var acceptance, nonGoals stringsFlag
	set.Var(&acceptance, "acceptance", "checklist item as id=explicit criterion (repeatable)")
	set.Var(&nonGoals, "non-goal", "explicit non-goal (repeatable)")
	if err := parseGoalFlags(set, args, nil); err != nil {
		return err
	}
	items := make([]goalpkg.ChecklistItem, 0, len(acceptance))
	for _, value := range acceptance {
		key, text, ok := strings.Cut(value, "=")
		if !ok {
			return errors.New("acceptance must use id=criterion")
		}
		items = append(items, goalpkg.ChecklistItem{ID: key, Acceptance: text})
	}
	j, err := goalpkg.New(*id, *intent, items, nonGoals, time.Now())
	if err != nil {
		return err
	}
	if err := (goalpkg.Store{Path: *journalPath}).Create(j); err != nil {
		return err
	}
	return writeJSON(stdout, j)
}

func goalStatus(args []string, stdout, stderr io.Writer) error {
	set, path := goalFlags("goal status", stderr)
	if err := parseGoalFlags(set, args, nil); err != nil {
		return err
	}
	j, err := (goalpkg.Store{Path: *path}).Load()
	if err != nil {
		return err
	}
	return writeJSON(stdout, j)
}

func goalAdd(args []string, stdout, stderr io.Writer) error {
	set, path := goalFlags("goal add", stderr)
	revision := revisionFlag(set)
	id := set.String("id", "", "checklist item id")
	acceptance := set.String("acceptance", "", "explicit acceptance criterion")
	if err := parseGoalFlags(set, args, revision); err != nil {
		return err
	}
	j, err := (goalpkg.Store{Path: *path}).Update(*revision, func(j *goalpkg.Journal) error {
		return j.AddChecklistItem(goalpkg.ChecklistItem{ID: *id, Acceptance: *acceptance}, time.Now())
	})
	if err != nil {
		return err
	}
	return writeJSON(stdout, j)
}

func goalCheck(args []string, stdout, stderr io.Writer) error {
	set, path := goalFlags("goal check", stderr)
	revision := revisionFlag(set)
	item := set.String("item", "", "acceptance checklist item id")
	evidence := evidenceFlags(set, "evidence")
	if err := parseGoalFlags(set, args, revision); err != nil {
		return err
	}
	records, err := evidence.values()
	if err != nil {
		return err
	}
	j, err := (goalpkg.Store{Path: *path}).Update(*revision, func(j *goalpkg.Journal) error {
		return j.CompleteItem(*item, records, time.Now())
	})
	if err != nil {
		return err
	}
	return writeJSON(stdout, j)
}

func goalEvidence(args []string, stdout, stderr io.Writer) error {
	set, path := goalFlags("goal evidence", stderr)
	revision := revisionFlag(set)
	phase := set.String("phase", "", "phase with an existing receipt")
	evidence := evidenceFlags(set, "evidence")
	if err := parseGoalFlags(set, args, revision); err != nil {
		return err
	}
	records, err := evidence.values()
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return errors.New("at least one evidence record is required")
	}
	j, err := (goalpkg.Store{Path: *path}).Update(*revision, func(j *goalpkg.Journal) error {
		for _, record := range records {
			if err := j.AddReceiptEvidence(goalpkg.Phase(*phase), record, time.Now()); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return writeJSON(stdout, j)
}

func goalAdvance(args []string, stdout, stderr io.Writer) error {
	set, path := goalFlags("goal advance", stderr)
	revision := revisionFlag(set)
	phase := set.String("phase", "", "current phase name")
	summary := set.String("summary", "", "phase outcome and findings")
	evidence := evidenceFlags(set, "evidence")
	outcome := set.String("outcome", "", "closure achieved outcome")
	cleanup := set.String("cleanup", "", "closure cleanup performed")
	var remaining stringsFlag
	set.Var(&remaining, "remaining", "closure remaining work as debt=summary or risk=summary (repeatable)")
	noRemaining := set.Bool("no-remaining", false, "closure explicitly has no remaining debt or risk")
	next := evidenceFlags(set, "next")
	if err := parseGoalFlags(set, args, revision); err != nil {
		return err
	}
	records, err := evidence.values()
	if err != nil {
		return err
	}
	receipt := goalpkg.Receipt{Phase: goalpkg.Phase(*phase), Summary: *summary, Evidence: records}
	if receipt.Phase == goalpkg.PhaseClosure {
		closure, err := closureDetails(*outcome, *cleanup, remaining, *noRemaining, next)
		if err != nil {
			return err
		}
		receipt.Closure = closure
	}
	j, err := (goalpkg.Store{Path: *path}).Update(*revision, func(j *goalpkg.Journal) error {
		return j.Advance(receipt, time.Now())
	})
	if err != nil {
		return err
	}
	return writeJSON(stdout, j)
}

func closureDetails(outcome, cleanup string, remaining stringsFlag, noRemaining bool, next *evidenceOptions) (*goalpkg.ClosureDetails, error) {
	items := make([]goalpkg.RemainingWork, 0, len(remaining))
	for _, value := range remaining {
		kind, text, ok := strings.Cut(value, "=")
		if !ok {
			return nil, errors.New("remaining must use debt=summary or risk=summary")
		}
		items = append(items, goalpkg.RemainingWork{Kind: goalpkg.RemainingKind(kind), Summary: text})
	}
	if noRemaining && len(items) > 0 {
		return nil, errors.New("--no-remaining conflicts with --remaining")
	}
	if !noRemaining && len(items) == 0 {
		return nil, errors.New("closure requires --remaining or --no-remaining")
	}
	nextWork, err := next.values()
	if err != nil {
		return nil, err
	}
	return &goalpkg.ClosureDetails{AchievedOutcome: outcome, Cleanup: cleanup, Remaining: items, NextWork: nextWork}, nil
}

// evidenceOptions collects one repeatable evidence triple. The three flags are
// positional with respect to each other, so an unequal count is a caller error
// rather than a silently truncated record.
type evidenceOptions struct{ kinds, references, results stringsFlag }

func evidenceFlags(set *flag.FlagSet, prefix string) *evidenceOptions {
	options := &evidenceOptions{}
	set.Var(&options.kinds, prefix+"-type", "command, file, link, commit, test, or issue (repeatable)")
	set.Var(&options.references, prefix+"-ref", "machine-resolvable evidence reference (repeatable)")
	set.Var(&options.results, prefix+"-result", "observed outcome (repeatable)")
	return options
}

func (e *evidenceOptions) values() ([]goalpkg.Evidence, error) {
	if len(e.kinds) != len(e.references) || len(e.kinds) != len(e.results) {
		return nil, fmt.Errorf("evidence flags must be repeated together: %d types, %d references, %d results", len(e.kinds), len(e.references), len(e.results))
	}
	records := make([]goalpkg.Evidence, 0, len(e.kinds))
	for index := range e.kinds {
		records = append(records, goalpkg.Evidence{Type: goalpkg.EvidenceType(e.kinds[index]), Reference: e.references[index], Result: e.results[index]})
	}
	return records, nil
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
