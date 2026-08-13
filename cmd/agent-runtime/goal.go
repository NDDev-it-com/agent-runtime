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

func goalEvidence(args []string, stdout, stderr io.Writer) error {
	set, path, revision, err := goalMutationFlags("goal evidence", args, stderr, true)
	if err != nil {
		return err
	}
	phase := set.String("phase", "", "phase with an existing receipt")
	evidence := evidenceFlags(set, "evidence")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *revision == 0 {
		return errors.New("--revision must be positive")
	}
	store := goalpkg.Store{Path: *path}
	j, err := store.Update(*revision, func(j *goalpkg.Journal) error {
		return j.AddReceiptEvidence(goalpkg.Phase(*phase), evidence.value(), time.Now())
	})
	if err != nil {
		return err
	}
	return writeJSON(stdout, j)
}

func goalAdd(args []string, stdout, stderr io.Writer) error {
	set, path, revision, err := goalMutationFlags("goal add", args, stderr, true)
	if err != nil {
		return err
	}
	id := set.String("id", "", "checklist item id")
	acceptance := set.String("acceptance", "", "explicit acceptance criterion")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *revision == 0 {
		return errors.New("--revision must be positive")
	}
	store := goalpkg.Store{Path: *path}
	j, err := store.Update(*revision, func(j *goalpkg.Journal) error {
		return j.AddChecklistItem(goalpkg.ChecklistItem{ID: *id, Acceptance: *acceptance}, time.Now())
	})
	if err != nil {
		return err
	}
	return writeJSON(stdout, j)
}

func goalInit(args []string, stdout, stderr io.Writer) error {
	set := flag.NewFlagSet("goal init", flag.ContinueOnError)
	set.SetOutput(stderr)
	journalPath := set.String("journal", ".agent-runtime/goal.json", "durable goal journal path")
	id := set.String("id", "", "stable goal identifier")
	intent := set.String("intent", "", "desired outcome")
	var acceptance, nonGoals stringsFlag
	set.Var(&acceptance, "acceptance", "checklist item as id=explicit criterion (repeatable)")
	set.Var(&nonGoals, "non-goal", "explicit non-goal (repeatable)")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return errors.New("unexpected positional arguments")
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
	set, path, _, err := goalMutationFlags("goal status", args, stderr, false)
	if err != nil {
		return err
	}
	_ = set
	j, err := (goalpkg.Store{Path: *path}).Load()
	if err != nil {
		return err
	}
	return writeJSON(stdout, j)
}

func goalCheck(args []string, stdout, stderr io.Writer) error {
	set, path, revision, err := goalMutationFlags("goal check", args, stderr, true)
	if err != nil {
		return err
	}
	item := set.String("item", "", "acceptance checklist item id")
	evidence := evidenceFlags(set, "evidence")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *revision == 0 {
		return errors.New("--revision must be positive")
	}
	store := goalpkg.Store{Path: *path}
	j, err := store.Update(*revision, func(j *goalpkg.Journal) error {
		return j.CompleteItem(*item, []goalpkg.Evidence{evidence.value()}, time.Now())
	})
	if err != nil {
		return err
	}
	return writeJSON(stdout, j)
}

func goalAdvance(args []string, stdout, stderr io.Writer) error {
	set, path, revision, err := goalMutationFlags("goal advance", args, stderr, true)
	if err != nil {
		return err
	}
	phase := set.String("phase", "", "current phase name")
	summary := set.String("summary", "", "phase outcome and findings")
	evidence := evidenceFlags(set, "evidence")
	outcome := set.String("outcome", "", "closure achieved outcome")
	cleanup := set.String("cleanup", "", "closure cleanup performed")
	var remaining stringsFlag
	set.Var(&remaining, "remaining", "closure remaining work as debt=summary or risk=summary (repeatable)")
	noRemaining := set.Bool("no-remaining", false, "closure explicitly has no remaining debt or risk")
	next := evidenceFlags(set, "next")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *revision == 0 {
		return errors.New("--revision must be positive")
	}
	receipt := goalpkg.Receipt{Phase: goalpkg.Phase(*phase), Summary: *summary, Evidence: []goalpkg.Evidence{evidence.value()}}
	if receipt.Phase == goalpkg.PhaseClosure {
		items := make([]goalpkg.RemainingWork, 0, len(remaining))
		for _, value := range remaining {
			kind, text, ok := strings.Cut(value, "=")
			if !ok {
				return errors.New("remaining must use debt=summary or risk=summary")
			}
			items = append(items, goalpkg.RemainingWork{Kind: goalpkg.RemainingKind(kind), Summary: text})
		}
		if *noRemaining && len(items) > 0 {
			return errors.New("--no-remaining conflicts with --remaining")
		}
		if !*noRemaining && len(items) == 0 {
			return errors.New("closure requires --remaining or --no-remaining")
		}
		nextWork := []goalpkg.Evidence{}
		if *next.kind != "" || *next.reference != "" || *next.result != "" {
			nextWork = append(nextWork, next.value())
		}
		receipt.Closure = &goalpkg.ClosureDetails{AchievedOutcome: *outcome, Cleanup: *cleanup, Remaining: items, NextWork: nextWork}
	}
	store := goalpkg.Store{Path: *path}
	j, err := store.Update(*revision, func(j *goalpkg.Journal) error {
		return j.Advance(receipt, time.Now())
	})
	if err != nil {
		return err
	}
	return writeJSON(stdout, j)
}

func goalMutationFlags(name string, args []string, stderr io.Writer, mutation bool) (*flag.FlagSet, *string, *uint64, error) {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(stderr)
	path := set.String("journal", ".agent-runtime/goal.json", "durable goal journal path")
	var revision *uint64
	if mutation {
		revision = set.Uint64("revision", 0, "required expected journal revision")
	} else {
		placeholder := uint64(0)
		revision = &placeholder
		if err := set.Parse(args); err != nil {
			return nil, nil, nil, err
		}
		if set.NArg() != 0 {
			return nil, nil, nil, errors.New("unexpected positional arguments")
		}
	}
	return set, path, revision, nil
}

type evidenceOptions struct{ kind, reference, result *string }

func evidenceFlags(set *flag.FlagSet, prefix string) evidenceOptions {
	return evidenceOptions{kind: set.String(prefix+"-type", "", "command, file, link, commit, test, or issue"), reference: set.String(prefix+"-ref", "", "machine-resolvable evidence reference"), result: set.String(prefix+"-result", "", "observed outcome")}
}
func (e evidenceOptions) value() goalpkg.Evidence {
	return goalpkg.Evidence{Type: goalpkg.EvidenceType(*e.kind), Reference: *e.reference, Result: *e.result}
}
func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
