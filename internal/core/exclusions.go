// Built-in false-positive exclusions, compiled into the binary from
// exclusions.toml. They complement the hash allowlist, which suppresses one
// exact value: an exclusion suppresses a value by its surrounding context, for
// false positives whose value differs on every occurrence.
//
// Embedded rather than read at runtime for the same reason as the local
// rules: a tool payload or an agent must not be able to extend the list.
package core

import (
	"bytes"
	_ "embed"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/betterleaks/betterleaks/config"
	"github.com/pelletier/go-toml/v2"
)

//go:embed exclusions.toml
var exclusionsTOML []byte

// exclusions is set by buildDetector, so a malformed list fails inside the
// CLI's panic boundary instead of at package init.
var exclusions []exclusion

type exclusion struct {
	ID          string   `toml:"id"`
	Description string   `toml:"description"`
	Rules       []string `toml:"rules"`
	Pattern     string   `toml:"pattern"`
	Examples    []string `toml:"examples"`

	re *regexp.Regexp
}

// parseExclusions validates every entry against the loaded rule set. An entry
// must name existing rules (a typo would otherwise be silently inert) and its
// pattern must have exactly one capture group, the span it excludes.
func parseExclusions(data []byte, cfg *config.Config) ([]exclusion, error) {
	var file struct {
		Exclusion []exclusion `toml:"exclusion"`
	}
	if err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(&file); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	for i := range file.Exclusion {
		e := &file.Exclusion[i]
		if e.ID == "" || e.Description == "" || e.Pattern == "" || len(e.Rules) == 0 || len(e.Examples) == 0 {
			return nil, fmt.Errorf("exclusion %d (%q): id, description, rules, pattern and examples are required", i, e.ID)
		}
		if seen[e.ID] {
			return nil, fmt.Errorf("exclusion %q: duplicate id", e.ID)
		}
		seen[e.ID] = true
		for _, rule := range e.Rules {
			if _, ok := cfg.Rules[rule]; !ok {
				return nil, fmt.Errorf("exclusion %q: unknown rule %q", e.ID, rule)
			}
		}
		re, err := regexp.Compile(e.Pattern)
		if err != nil {
			return nil, fmt.Errorf("exclusion %q: %w", e.ID, err)
		}
		if re.NumSubexp() != 1 {
			return nil, fmt.Errorf("exclusion %q: pattern must have exactly one capture group", e.ID)
		}
		e.re = re
	}
	return file.Exclusion, nil
}

// isExcluded reports whether an exclusion for ruleID has a match whose capture
// group contains the secret. [start, end) is the whole rule match, which
// usually includes the key name and a trailing delimiter, so the secret is
// located inside it. A decoded secret does not appear in the raw text; its
// encoded span stands in for it. An unusable span (0, 0) never matches, so a
// span-mapping failure fails closed.
func isExcluded(text, ruleID, secret string, start, end int) bool {
	if start >= end {
		return false
	}
	if i := strings.LastIndex(text[start:end], secret); secret != "" && i >= 0 {
		start, end = start+i, start+i+len(secret)
	}
	for _, e := range exclusions {
		if !slices.Contains(e.Rules, ruleID) {
			continue
		}
		for _, m := range e.re.FindAllStringSubmatchIndex(text, -1) {
			if m[2] <= start && end <= m[3] {
				return true
			}
		}
	}
	return false
}
