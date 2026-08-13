// SPDX-License-Identifier: AGPL-3.0-only

package observability

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

type Policy struct{ MaxSensitivity Sensitivity }

func DefaultPolicy() Policy { return Policy{MaxSensitivity: SensitivityInternal} }

type sanitizer struct {
	policy Policy
	counts map[RedactionReason]uint32
	seen   map[visit]bool
}
type visit struct {
	typ reflect.Type
	ptr uintptr
}

var unsafeFragments = []string{"authorization", "bearer", "credential", "password", "passwd", "secret", "token", "api_key", "apikey", "private_key", "command", "argv", "environment", "env_value", "provider", "prompt", "raw", "url", "uri", "dsn", "connection_string"}

func (p Policy) Redact(inputs []InputAttribute) ([]Attribute, []RedactionDecision, error) {
	if !validSensitivity(p.MaxSensitivity) {
		return nil, nil, errors.New("invalid maximum sensitivity")
	}
	s := sanitizer{policy: p, counts: map[RedactionReason]uint32{}, seen: map[visit]bool{}}
	ordered := append([]InputAttribute(nil), inputs...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	if len(ordered) > MaxAttributes {
		s.counts[ReasonAttributeLimit] += uint32(len(ordered) - MaxAttributes)
		ordered = ordered[:MaxAttributes]
	}
	out := make([]Attribute, 0, len(ordered))
	last := ""
	for _, input := range ordered {
		if !validAttributeName(input.Name) || unsafeName(input.Name) {
			s.counts[ReasonUnsafeName]++
			continue
		}
		if input.Name == last {
			return nil, nil, fmt.Errorf("duplicate attribute %q", input.Name)
		}
		last = input.Name
		if !allowedSensitivity(input.Sensitivity, p.MaxSensitivity) {
			s.counts[ReasonSensitivity]++
			continue
		}
		value, ok := s.value(reflect.ValueOf(input.Value), input.Sensitivity, 0)
		if !ok {
			continue
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			s.counts[ReasonUnsupported]++
			continue
		}
		out = append(out, Attribute{Name: input.Name, Sensitivity: input.Sensitivity, Value: append(json.RawMessage(nil), encoded...)})
	}
	return out, s.decisions(), nil
}

func (s *sanitizer) value(v reflect.Value, sensitivity Sensitivity, depth int) (any, bool) {
	if depth > MaxDepth {
		s.counts[ReasonDepth]++
		return "[REDACTED]", true
	}
	if !v.IsValid() {
		return nil, true
	}
	if v.CanInterface() {
		candidate := v.Interface()
		if _, ok := candidate.(error); ok {
			s.counts[ReasonUnsupported]++
			return "[REDACTED]", true
		}
		if _, ok := candidate.(fmt.Stringer); ok {
			s.counts[ReasonUnsupported]++
			return "[REDACTED]", true
		}
	}
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return nil, true
		}
		return s.value(v.Elem(), sensitivity, depth+1)
	case reflect.Pointer:
		if v.IsNil() {
			return nil, true
		}
		key := visit{v.Type(), v.Pointer()}
		if s.seen[key] {
			s.counts[ReasonCycle]++
			return "[REDACTED]", true
		}
		s.seen[key] = true
		defer delete(s.seen, key)
		return s.value(v.Elem(), sensitivity, depth+1)
	case reflect.Bool:
		return v.Bool(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int(), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint(), true
	case reflect.Float32, reflect.Float64:
		f := v.Float()
		if f != f || f > 1.7976931348623157e308 || f < -1.7976931348623157e308 {
			s.counts[ReasonUnsupported]++
			return "[REDACTED]", true
		}
		return f, true
	case reflect.String:
		return s.stringValue(v.String())
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return nil, true
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			s.counts[ReasonBinary]++
			return "[REDACTED]", true
		}
		key := visit{v.Type(), 0}
		if v.Kind() == reflect.Slice {
			key.ptr = v.Pointer()
			if s.seen[key] {
				s.counts[ReasonCycle]++
				return "[REDACTED]", true
			}
			s.seen[key] = true
			defer delete(s.seen, key)
		}
		limit := v.Len()
		if limit > MaxCollectionItems {
			s.counts[ReasonCollection] += uint32(limit - MaxCollectionItems)
			limit = MaxCollectionItems
		}
		out := make([]any, 0, limit)
		for i := 0; i < limit; i++ {
			item, _ := s.value(v.Index(i), sensitivity, depth+1)
			out = append(out, item)
		}
		return out, true
	case reflect.Map:
		if v.IsNil() {
			return nil, true
		}
		if v.Type().Key().Kind() != reflect.String {
			s.counts[ReasonUnsupported]++
			return "[REDACTED]", true
		}
		key := visit{v.Type(), v.Pointer()}
		if s.seen[key] {
			s.counts[ReasonCycle]++
			return "[REDACTED]", true
		}
		s.seen[key] = true
		defer delete(s.seen, key)
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		if len(keys) > MaxCollectionItems {
			s.counts[ReasonCollection] += uint32(len(keys) - MaxCollectionItems)
			keys = keys[:MaxCollectionItems]
		}
		out := make(map[string]any, len(keys))
		for _, mapKey := range keys {
			name := mapKey.String()
			if !validNestedName(name) {
				s.counts[ReasonUnsafeName]++
				continue
			}
			if unsafeName(name) {
				s.counts[ReasonUnsafeName]++
				continue
			}
			item, _ := s.value(v.MapIndex(mapKey), sensitivity, depth+1)
			out[name] = item
		}
		return out, true
	default:
		s.counts[ReasonUnsupported]++
		return "[REDACTED]", true
	}
}

func (s *sanitizer) stringValue(value string) (string, bool) {
	if !utf8.ValidString(value) {
		s.counts[ReasonInvalidUTF8]++
		value = strings.ToValidUTF8(value, "�")
	}
	normalized := strings.ToLower(strings.TrimSpace(value))
	if strings.Contains(normalized, "://") || strings.HasPrefix(normalized, "bearer ") || strings.HasPrefix(normalized, "basic ") || strings.HasPrefix(normalized, "ghp_") || strings.HasPrefix(normalized, "github_pat_") || strings.HasPrefix(normalized, "sk-") {
		s.counts[ReasonUnsafeValue]++
		return "[REDACTED]", true
	}
	if len(value) <= MaxStringBytes {
		return value, true
	}
	s.counts[ReasonString]++
	value = value[:MaxStringBytes]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value, true
}
func (s *sanitizer) decisions() []RedactionDecision {
	reasons := make([]string, 0, len(s.counts))
	for reason, count := range s.counts {
		if count > 0 {
			reasons = append(reasons, string(reason))
		}
	}
	sort.Strings(reasons)
	out := make([]RedactionDecision, 0, len(reasons))
	for _, reason := range reasons {
		out = append(out, RedactionDecision{Reason: RedactionReason(reason), Count: s.counts[RedactionReason(reason)]})
	}
	return out
}
func unsafeName(name string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(name))
	for _, fragment := range unsafeFragments {
		fragment = strings.NewReplacer("_", "", "-", "", ".", "").Replace(fragment)
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}
func validAttributeName(name string) bool {
	return len(name) > 0 && len(name) <= 64 && regexpAttribute.MatchString(name)
}
func validNestedName(name string) bool {
	return len(name) > 0 && len(name) <= 64 && regexpNested.MatchString(name)
}

var regexpAttribute = regexpMust(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
var regexpNested = regexpMust(`^[A-Za-z][A-Za-z0-9_.-]*$`)

func regexpMust(pattern string) *regexp.Regexp { return regexp.MustCompile(pattern) }
func validSensitivity(v Sensitivity) bool {
	return v == SensitivityPublic || v == SensitivityInternal || v == SensitivityConfidential || v == SensitivitySecret
}
func allowedSensitivity(value, max Sensitivity) bool {
	if value == SensitivitySecret {
		return false
	}
	rank := func(v Sensitivity) int {
		switch v {
		case SensitivityPublic:
			return 1
		case SensitivityInternal:
			return 2
		case SensitivityConfidential:
			return 3
		case SensitivitySecret:
			return 4
		}
		return 99
	}
	return validSensitivity(value) && rank(value) <= rank(max)
}
