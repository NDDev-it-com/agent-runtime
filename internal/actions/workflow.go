// SPDX-License-Identifier: AGPL-3.0-only

// Package actions parses a GitHub Actions workflow into the semantic model this
// repository's contracts reason about.
//
// It exists because the contracts previously matched workflow text. A required
// command could be moved into a comment, a disabled job, an unrelated step or a
// scalar that never executes, and every checker stayed green while the property
// it is named after was gone. Text has no notion of "this runs"; this model
// does, and nothing outside an enabled step of an enabled job is evidence.
//
// The model is deliberately narrow. Constructs this repository does not use are
// rejected at parse time rather than approximated, because an approximation is
// exactly the failure being fixed: anchors and aliases can express the same
// value in two places, and duplicate keys let a file mean two things at once.
// A workflow that cannot be modelled exactly is a workflow no contract may
// claim to have verified.
package actions

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// Workflow is one parsed workflow file.
type Workflow struct {
	Name        string
	Triggers    map[string]Trigger
	Permissions map[string]string
	Env         map[string]string
	Jobs        map[string]*Job
	// JobOrder preserves file order so diagnostics name jobs the way a reader
	// sees them.
	JobOrder []string
}

// Trigger is one entry under `on`. Present distinguishes a declared trigger
// with no filters from an absent one, which YAML renders identically as nil.
type Trigger struct {
	Present     bool
	Branches    []string
	Tags        []string
	Paths       []string
	PathsIgnore []string
}

// Job is one entry under `jobs`.
type Job struct {
	ID string
	// Name is an explicit `name:` override. NameSet separates "absent", which
	// leaves the check name equal to the job ID, from an empty string.
	Name    string
	NameSet bool
	// If holds a job-level condition verbatim. Enabled reports whether it
	// permits execution.
	If             string
	RunsOn         string
	Permissions    map[string]string
	PermissionsSet bool
	// PermissionsBlanket holds a scalar `permissions:` such as write-all. It is
	// modelled rather than rejected so a contract can refuse it by name.
	PermissionsBlanket string
	Matrix             map[string][]string
	Env                map[string]string
	Steps              []Step
	// Environment, Secrets and UsesWorkflow are surfaces this repository's
	// release contract forbids. They are modelled so their absence is a checked
	// property rather than the parser happening not to look.
	Environment  string
	SecretsSet   bool
	UsesWorkflow string
}

// Step is one entry under a job's `steps`.
type Step struct {
	Name string
	If   string
	Uses string
	Run  string
	With map[string]string
	Env  map[string]string
}

// Enabled reports whether this step runs when its job runs. A literal false
// condition is the only form this repository uses; anything else is treated as
// potentially executing, because assuming a condition is false is how a control
// silently disappears.
func (s Step) Enabled() bool { return !literalFalse(s.If) }

// Enabled reports whether the job runs at all.
func (j *Job) Enabled() bool { return !literalFalse(j.If) }

func literalFalse(condition string) bool {
	switch strings.TrimSpace(strings.ToLower(condition)) {
	case "false", "${{ false }}", "${{false}}":
		return true
	}
	return false
}

// RunScripts returns the executable part of the `run` body of every enabled
// step, in order. This is the only surface a command may be claimed to execute
// from, and shell comments are stripped: `# go run ./cmd/check-signature` is
// prose that happens to sit inside a script, exactly as much as a YAML comment
// is prose that happens to sit inside a file.
func (j *Job) RunScripts() []string {
	scripts := make([]string, 0, len(j.Steps))
	for _, step := range j.Steps {
		if step.Enabled() && step.Run != "" {
			if script := executableScript(step.Run); strings.TrimSpace(script) != "" {
				scripts = append(scripts, script)
			}
		}
	}
	return scripts
}

// executableScript removes POSIX shell comments. A `#` only opens a comment
// when it is unquoted and begins a word, so quoting state is tracked rather
// than guessed; anything the scanner is unsure about is kept, because dropping
// a real command would weaken the very count this exists to make honest.
func executableScript(script string) string {
	var out strings.Builder
	out.Grow(len(script))
	for _, line := range strings.Split(script, "\n") {
		var single, double, escaped bool
		cut := -1
		for i, r := range line {
			switch {
			case escaped:
				escaped = false
			case double && r == '\\':
				escaped = true
			case r == '\'' && !double:
				single = !single
			case r == '"' && !single:
				double = !double
			case r == '#' && !single && !double && (i == 0 || isShellSpace(rune(line[i-1]))):
				cut = i
			}
			if cut >= 0 {
				break
			}
		}
		if cut >= 0 {
			line = line[:cut]
		}
		out.WriteString(strings.TrimRight(line, " \t"))
		out.WriteByte('\n')
	}
	return out.String()
}

func isShellSpace(r rune) bool { return r == ' ' || r == '\t' }

// CountRunOccurrences reports how many times token appears across this job's
// executed run scripts. Occurrences in comments, step names, `with` values and
// disabled steps are not counted, because none of them executes.
func (j *Job) CountRunOccurrences(token string) int {
	total := 0
	for _, script := range j.RunScripts() {
		total += strings.Count(script, token)
	}
	return total
}

// StepUsing returns the first enabled step whose action reference starts with
// prefix, which is how a caller finds a well-known action without pinning its
// position in the step list.
func (j *Job) StepUsing(prefix string) (Step, bool) {
	for _, step := range j.Steps {
		if step.Enabled() && strings.HasPrefix(step.Uses, prefix) {
			return step, true
		}
	}
	return Step{}, false
}

// UsesActions returns the `uses` reference of every enabled step.
func (j *Job) UsesActions() []string {
	refs := make([]string, 0, len(j.Steps))
	for _, step := range j.Steps {
		if step.Enabled() && step.Uses != "" {
			refs = append(refs, step.Uses)
		}
	}
	return refs
}

// EnabledJobs returns jobs that run, in file order.
func (w *Workflow) EnabledJobs() []*Job {
	jobs := make([]*Job, 0, len(w.JobOrder))
	for _, id := range w.JobOrder {
		if job := w.Jobs[id]; job != nil && job.Enabled() {
			jobs = append(jobs, job)
		}
	}
	return jobs
}

// CountRunOccurrences reports how many times token appears across every
// executed run script in the workflow.
func (w *Workflow) CountRunOccurrences(token string) int {
	total := 0
	for _, job := range w.EnabledJobs() {
		total += job.CountRunOccurrences(token)
	}
	return total
}

// UsesActions returns the action reference of every enabled step in every
// enabled job.
func (w *Workflow) UsesActions() []string {
	var refs []string
	for _, job := range w.EnabledJobs() {
		refs = append(refs, job.UsesActions()...)
	}
	return refs
}

// StepValues returns every scalar a runner would read from enabled steps that
// is not a run script: action references and `with` and `env` values. A
// contract uses it to forbid a surface appearing anywhere that takes effect.
func (w *Workflow) StepValues() []string {
	var values []string
	for _, job := range w.EnabledJobs() {
		values = append(values, job.RunsOn, job.Environment, job.UsesWorkflow)
		for _, value := range job.Env {
			values = append(values, value)
		}
		for _, step := range job.Steps {
			if !step.Enabled() {
				continue
			}
			values = append(values, step.Uses)
			for _, value := range step.With {
				values = append(values, value)
			}
			for _, value := range step.Env {
				values = append(values, value)
			}
		}
	}
	return values
}

// Job returns an enabled job by ID. A disabled job is reported as missing
// rather than returned, so a caller cannot accidentally accept it as evidence.
func (w *Workflow) Job(id string) (*Job, error) {
	job, ok := w.Jobs[id]
	if !ok {
		return nil, fmt.Errorf("workflow has no job %q", id)
	}
	if !job.Enabled() {
		return nil, fmt.Errorf("workflow job %q is disabled by its condition %q", id, job.If)
	}
	return job, nil
}

// Parse builds the model, refusing anything it cannot represent exactly.
func Parse(data []byte) (*Workflow, error) {
	// The decoder rejects duplicate mapping keys on its own, so a file that
	// asserts two values for one key never reaches the model.
	file, err := parser.ParseBytes(data, 0)
	if err != nil {
		return nil, fmt.Errorf("parse workflow: %w", err)
	}
	if len(file.Docs) != 1 {
		return nil, fmt.Errorf("parse workflow: expected one document, found %d", len(file.Docs))
	}
	body := file.Docs[0].Body
	if err := rejectUnmodelled(body); err != nil {
		return nil, err
	}
	var raw rawWorkflow
	if err := yaml.NodeToValue(body, &raw); err != nil {
		return nil, fmt.Errorf("parse workflow: %w", err)
	}
	jobs, err := jobsMapping(body)
	if err != nil {
		return nil, err
	}
	return raw.model(jobs)
}

// rejectUnmodelled fails closed on YAML this model cannot represent without
// ambiguity: anchors and aliases place one value in two locations, so a control
// could appear to be present at a location that never executes.
func rejectUnmodelled(body ast.Node) error {
	var found ast.Node
	ast.Walk(visitorFunc(func(n ast.Node) {
		if found != nil {
			return
		}
		switch n.(type) {
		case *ast.AliasNode, *ast.AnchorNode:
			found = n
		}
	}), body)
	if found != nil {
		return fmt.Errorf("parse workflow: YAML anchors and aliases are not permitted (%s); a control must appear where it executes", found.GetToken().Position)
	}
	return nil
}

type visitorFunc func(ast.Node)

func (v visitorFunc) Visit(n ast.Node) ast.Visitor { v(n); return v }

// jobsMapping returns the `jobs` mapping in file order, so diagnostics and
// iteration follow what a reader sees rather than Go map order.
func jobsMapping(body ast.Node) ([]*ast.MappingValueNode, error) {
	mapping, ok := body.(*ast.MappingNode)
	if !ok {
		return nil, errors.New("parse workflow: document must be a mapping")
	}
	for _, entry := range mapping.Values {
		if entry.Key.GetToken().Value != "jobs" {
			continue
		}
		switch value := entry.Value.(type) {
		case *ast.MappingNode:
			return value.Values, nil
		case *ast.MappingValueNode:
			return []*ast.MappingValueNode{value}, nil
		default:
			return nil, errors.New("parse workflow: jobs must be a mapping")
		}
	}
	return nil, errors.New("parse workflow: no jobs")
}

type rawWorkflow struct {
	Name string `yaml:"name"`
	// A trigger with no filters decodes to a nil entry whose key is still
	// present, which is how "declared" is told apart from "absent".
	On          map[string]*rawOn `yaml:"on"`
	Permissions map[string]string `yaml:"permissions"`
	Env         map[string]any    `yaml:"env"`
}

type rawOn struct {
	Branches    []string `yaml:"branches"`
	Tags        []string `yaml:"tags"`
	Paths       []string `yaml:"paths"`
	PathsIgnore []string `yaml:"paths-ignore"`
}

type rawJob struct {
	Name        *string        `yaml:"name"`
	If          string         `yaml:"if"`
	RunsOn      string         `yaml:"runs-on"`
	Permissions any            `yaml:"permissions"`
	Strategy    rawStrategy    `yaml:"strategy"`
	Env         map[string]any `yaml:"env"`
	Steps       []rawStep      `yaml:"steps"`
	Environment string         `yaml:"environment"`
	Secrets     any            `yaml:"secrets"`
	Uses        string         `yaml:"uses"`
}

type rawStrategy struct {
	Matrix map[string]any `yaml:"matrix"`
}

type rawStep struct {
	Name string         `yaml:"name"`
	If   string         `yaml:"if"`
	Uses string         `yaml:"uses"`
	Run  string         `yaml:"run"`
	With map[string]any `yaml:"with"`
	Env  map[string]any `yaml:"env"`
}

func (r rawWorkflow) model(jobs []*ast.MappingValueNode) (*Workflow, error) {
	w := &Workflow{
		Name:        r.Name,
		Triggers:    make(map[string]Trigger, len(r.On)),
		Permissions: r.Permissions,
		Env:         scalarMap(r.Env),
		Jobs:        map[string]*Job{},
	}
	for name, on := range r.On {
		trigger := Trigger{Present: true}
		if on != nil {
			trigger.Branches, trigger.Tags = on.Branches, on.Tags
			trigger.Paths, trigger.PathsIgnore = on.Paths, on.PathsIgnore
		}
		w.Triggers[name] = trigger
	}
	if len(jobs) == 0 {
		return nil, errors.New("parse workflow: no jobs")
	}
	for _, entry := range jobs {
		id := entry.Key.GetToken().Value
		var raw rawJob
		if err := yaml.NodeToValue(entry.Value, &raw); err != nil {
			return nil, fmt.Errorf("parse workflow job %q: %w", id, err)
		}
		if _, duplicate := w.Jobs[id]; duplicate {
			return nil, fmt.Errorf("parse workflow: duplicate job %q", id)
		}
		job := &Job{
			ID:           id,
			If:           raw.If,
			RunsOn:       raw.RunsOn,
			Matrix:       map[string][]string{},
			Env:          scalarMap(raw.Env),
			Environment:  raw.Environment,
			SecretsSet:   raw.Secrets != nil,
			UsesWorkflow: raw.Uses,
		}
		switch permissions := raw.Permissions.(type) {
		case nil:
		case string:
			job.PermissionsBlanket, job.PermissionsSet = permissions, true
		case map[string]any:
			job.Permissions, job.PermissionsSet = scalarMap(permissions), true
		default:
			return nil, fmt.Errorf("parse workflow job %q: permissions must be a scalar or a mapping", id)
		}
		if raw.Name != nil {
			job.Name, job.NameSet = *raw.Name, true
		}
		for key, value := range raw.Strategy.Matrix {
			list, ok := value.([]any)
			if !ok {
				// fail-fast, include and exclude are not lanes. Recording them
				// as empty would make a dropped lane look like a key that was
				// never a lane in the first place.
				continue
			}
			lanes := make([]string, 0, len(list))
			for _, lane := range list {
				lanes = append(lanes, scalarString(lane))
			}
			job.Matrix[key] = lanes
		}
		for _, step := range raw.Steps {
			job.Steps = append(job.Steps, Step{
				Name: step.Name,
				If:   step.If,
				Uses: step.Uses,
				Run:  step.Run,
				With: scalarMap(step.With),
				Env:  scalarMap(step.Env),
			})
		}
		w.Jobs[id] = job
		w.JobOrder = append(w.JobOrder, id)
	}
	return w, nil
}

// scalarMap renders values as the literal text a runner would see, so a
// contract comparing against a pinned string sees what Actions sees.
func scalarMap(in map[string]any) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out[key] = scalarString(in[key])
	}
	return out
}

func scalarString(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprint(value)
}
