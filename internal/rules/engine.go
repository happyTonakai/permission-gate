package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/happyTonakai/permission-gate/internal/analyze"
	"github.com/happyTonakai/permission-gate/internal/config"
	"github.com/happyTonakai/permission-gate/internal/verdict"
)

// Engine evaluates commands against allow/deny/ask rules. All rules —
// builtin and user, all three tiers — are merged into a single ordered
// list. The first rule that matches the command wins.
//
// Ordering rule (driven by MergeMode):
//   - prepend  (default): user rules come first, builtin rules last.
//     User allow therefore overrides builtin deny for the same command.
//   - append:  builtin rules come first, user rules last.
//     Builtin deny therefore wins unless the user has no matching rule.
//   - overwrite: user rules only; builtin rules are dropped entirely.
//
// The engine emits user tiers in [allow] → [deny] → [ask] order so the
// on-disk segment order matches the priority order in the merged list.
// Flag-level denies (cfg.Deny.Flags + builtin deny-flags) are converted
// into virtual deny specs that participate in the same first-match-wins
// logic, so a dangerous flag can still block a command even when an
// allow rule for the base command would otherwise match.
type Engine struct {
	patterns []pattern
}

type pattern struct {
	spec   config.CommandSpec
	raw    string
	source string
	tier   verdict.Level
}

// New creates a rule engine from config, merge mode, and built-in rules.
// Returns an error if any inline-table spec in the user config fails to
// parse — better to surface a misconfigured rule than to silently drop it.
func New(cfg *config.Config, mode config.MergeMode, builtinAllow, builtinDeny, builtinAsk []string, builtinDenyFlags map[string][]string) (*Engine, error) {
	e := &Engine{}

	// Load user specs from raw. Within each tier, the on-disk order of
	// project + global is preserved, controlled by the merge mode:
	//   - prepend  (default): project before global
	//   - append:             global before project
	//   - overwrite:          project only
	loadUserTier := func(globalRules, projectRules *config.RawRules) ([]config.CommandSpec, error) {
		g, err := globalRules.Specs()
		if err != nil {
			return nil, fmt.Errorf("global config: %w", err)
		}
		p, err := projectRules.Specs()
		if err != nil {
			return nil, fmt.Errorf("project config: %w", err)
		}
		switch mode {
		case config.MergeAppend:
			return append(append([]config.CommandSpec{}, g...), p...), nil
		case config.MergeOverwrite:
			return p, nil
		default:
			return append(append([]config.CommandSpec{}, p...), g...), nil
		}
	}
	userAllowSpecsData, err := loadUserTier(&cfg.GlobalRaw.Allow, &cfg.ProjectRaw.Allow)
	if err != nil {
		return nil, err
	}
	userAllowSpecs := specsToPatterns(userAllowSpecsData, "user", verdict.LevelAllow)

	userDenySpecsData, err := loadUserTier(&cfg.GlobalRaw.Deny, &cfg.ProjectRaw.Deny)
	if err != nil {
		return nil, err
	}
	userDenySpecs := specsToPatterns(userDenySpecsData, "user", verdict.LevelDeny)

	userAskSpecsData, err := loadUserTier(&cfg.GlobalRaw.Ask, &cfg.ProjectRaw.Ask)
	if err != nil {
		return nil, err
	}
	userAskSpecs := specsToPatterns(userAskSpecsData, "user", verdict.LevelAsk)
	userFlagSpecs := flagsToDenyPatterns(cfg.Deny.Flags, "user")

	var builtinAllowSpecs, builtinDenySpecs, builtinAskSpecs, builtinFlagSpecs []pattern
	if mode != config.MergeOverwrite {
		builtinAllowSpecs = stringsToPatterns(builtinAllow, "builtin", verdict.LevelAllow)
		builtinDenySpecs = stringsToPatterns(builtinDeny, "builtin", verdict.LevelDeny)
		builtinAskSpecs = stringsToPatterns(builtinAsk, "builtin", verdict.LevelAsk)
		builtinFlagSpecs = flagsToDenyPatterns(builtinDenyFlags, "builtin")
	}

	// Each source's segments are emitted in deny → flagDeny → ask → allow
	// order so that within a source the deny tier (including flag-based
	// denies) is consulted before any ask/allow tier.
	compose := func(deny, flagDeny, ask, allow []pattern) []pattern {
		out := make([]pattern, 0, len(deny)+len(flagDeny)+len(ask)+len(allow))
		out = append(out, deny...)
		out = append(out, flagDeny...)
		out = append(out, ask...)
		out = append(out, allow...)
		return out
	}
	user := compose(userDenySpecs, userFlagSpecs, userAskSpecs, userAllowSpecs)
	builtin := compose(builtinDenySpecs, builtinFlagSpecs, builtinAskSpecs, builtinAllowSpecs)

	switch mode {
	case config.MergeAppend:
		e.patterns = append(builtin, user...)
	case config.MergeOverwrite:
		e.patterns = user
	default: // prepend, or empty (treat as prepend)
		e.patterns = append(user, builtin...)
	}

	return e, nil
}

func specsToPatterns(specs []config.CommandSpec, source string, tier verdict.Level) []pattern {
	out := make([]pattern, 0, len(specs))
	for _, s := range specs {
		out = append(out, pattern{
			spec:   s,
			raw:    describeSpec(s),
			source: source,
			tier:   tier,
		})
	}
	return out
}

func stringsToPatterns(rules []string, source string, tier verdict.Level) []pattern {
	out := make([]pattern, 0, len(rules))
	for _, r := range rules {
		out = append(out, pattern{
			spec:   config.CommandSpec{Cmd: r},
			raw:    r,
			source: source,
			tier:   tier,
		})
	}
	return out
}

// flagsToDenyPatterns converts a cmd → flags map into a list of virtual
// deny specs, one per command, that match only when the dangerous flag
// is present. Commands with an empty flag list are skipped — otherwise the
// spec would match every invocation of that command (no IncludeFlags means
// "no constraint", not "match all").
func flagsToDenyPatterns(flags map[string][]string, source string) []pattern {
	out := make([]pattern, 0, len(flags))
	for cmd, flagList := range flags {
		if len(flagList) == 0 {
			continue
		}
		flagCopy := append([]string(nil), flagList...)
		out = append(out, pattern{
			spec: config.CommandSpec{
				Cmd:          cmd,
				IncludeFlags: flagCopy,
			},
			raw:    cmd + " (dangerous flags)",
			source: source,
			tier:   verdict.LevelDeny,
		})
	}
	return out
}

func describeSpec(s config.CommandSpec) string {
	if len(s.IncludeFlags) == 0 && len(s.ExcludeFlags) == 0 &&
		len(s.IncludeArgs) == 0 && len(s.ExcludeArgs) == 0 {
		return s.Cmd
	}
	var b strings.Builder
	b.WriteString(s.Cmd)
	appendList(&b, "include_flags", s.IncludeFlags)
	appendList(&b, "exclude_flags", s.ExcludeFlags)
	appendList(&b, "include_args", s.IncludeArgs)
	appendList(&b, "exclude_args", s.ExcludeArgs)
	return b.String()
}

func appendList(b *strings.Builder, name string, vs []string) {
	if len(vs) == 0 {
		return
	}
	b.WriteString(" ")
	b.WriteString(name)
	b.WriteString("=[")
	b.WriteString(strings.Join(vs, ","))
	b.WriteString("]")
}

// Check evaluates a single extracted command against the rules. The first
// pattern that matches wins, regardless of tier — this is how user allow
// can override builtin deny under prepend mode.
func (e *Engine) Check(cmd analyze.ExtractedCommand) verdict.Verdict {
	for _, p := range e.patterns {
		if !matchSpec(p.spec, cmd) {
			continue
		}
		switch p.tier {
		case verdict.LevelDeny:
			return verdict.Deny(p.source+" deny: "+p.raw, p.raw)
		case verdict.LevelAsk:
			return verdict.Ask(p.source + " ask: " + p.raw)
		case verdict.LevelAllow:
			return verdict.Allow(p.source+" allow: "+p.raw, p.raw)
		}
	}

	return verdict.Ask("unknown command, requires confirmation")
}

// Evaluate parses a raw command and returns the result for all segments.
func (e *Engine) Evaluate(rawCmd string) *verdict.Result {
	result := &verdict.Result{RawCommand: rawCmd}

	commands, err := analyze.ExtractCommands(rawCmd)
	if err != nil {
		result.Final = verdict.Ask("failed to parse command: " + err.Error())
		return result
	}

	if len(commands) == 0 {
		result.Final = verdict.Allow("no commands to execute", "")
		return result
	}

	var deniedCmds, askedCmds []string

	for _, cmd := range commands {
		v := e.Check(cmd)
		result.Segments = append(result.Segments, verdict.SegmentResult{
			Command: cmd.Raw,
			Tokens:  cmd.Tokens,
			Verdict: v,
		})
		switch v.Level {
		case verdict.LevelDeny:
			deniedCmds = append(deniedCmds, cmd.Raw)
		case verdict.LevelAsk:
			askedCmds = append(askedCmds, cmd.Raw)
		}
	}

	switch {
	case len(deniedCmds) > 0:
		result.Final = verdict.Deny("denied: "+strings.Join(deniedCmds, ", "), "")
	case len(askedCmds) == 0:
		result.Final = verdict.Allow("all commands are allowed", "")
	default:
		result.Final = verdict.Ask("needs confirmation: "+strings.Join(askedCmds, ", "))
	}

	return result
}

// matchSpec evaluates whether a command matches a CommandSpec.
// All refinement fields are AND-combined; any failure returns false.
func matchSpec(spec config.CommandSpec, cmd analyze.ExtractedCommand) bool {
	cmdTokens := strings.Fields(spec.Cmd)
	if len(cmdTokens) == 0 {
		return false
	}
	if !cmd.Match(cmdTokens) {
		return false
	}

	flagSet := cmd.ExpandedFlagSet()
	nonFlagArgs := cmd.NonFlagArgs()

	// Excludes win per field: any hit disqualifies the spec.
	if hasAnyFlag(flagSet, spec.ExcludeFlags) {
		return false
	}
	if hasAnyArgUnder(nonFlagArgs, spec.ExcludeArgs) {
		return false
	}

	// Includes only constrain when non-empty.
	if !includesAnyFlag(flagSet, spec.IncludeFlags) {
		return false
	}
	if !allArgsUnder(nonFlagArgs, spec.IncludeArgs) {
		return false
	}
	return true
}

func hasAnyFlag(flagSet map[string]struct{}, flags []string) bool {
	for _, f := range flags {
		if _, hit := flagSet[f]; hit {
			return true
		}
	}
	return false
}

// includesAnyFlag returns true if at least one entry in required matches
// some flag in flagSet. Required == nil is treated as "no constraint"
// (returns true) so callers can pass it unconditionally.
func includesAnyFlag(flagSet map[string]struct{}, required []string) bool {
	if len(required) == 0 {
		return true
	}
	for _, f := range required {
		if flagMatches(flagSet, f) {
			return true
		}
	}
	return false
}

func hasAnyArgUnder(args []string, prefixes []string) bool {
	for _, prefix := range prefixes {
		for _, arg := range args {
			if pathUnderOrEqual(arg, prefix) {
				return true
			}
		}
	}
	return false
}

// allArgsUnder returns true if every arg lives under some prefix.
// Required == nil is treated as "no constraint" (returns true).
func allArgsUnder(args []string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, arg := range args {
		ok := false
		for _, prefix := range prefixes {
			if pathUnderOrEqual(arg, prefix) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// flagMatches reports whether f matches any flag present in flagSet.
// Short option bundles on f are expanded so a spec entry of "-rf" matches
// commands with -r, -f, -rf, -fr, etc. Longer entries (-exec, -name) are
// treated as long options and only match verbatim.
func flagMatches(flagSet map[string]struct{}, f string) bool {
	if f == "" {
		return false
	}
	if _, hit := flagSet[f]; hit {
		return true
	}
	if !strings.HasPrefix(f, "-") || strings.HasPrefix(f, "--") || len(f) < 2 {
		return false
	}
	if !analyze.IsShortBundle(f) {
		return false
	}
	for i := 1; i < len(f); i++ {
		if _, hit := flagSet["-"+string(f[i])]; hit {
			return true
		}
	}
	return false
}

// pathUnderOrEqual reports whether path equals prefix or sits beneath it.
// Both sides are normalized first so /tmp/../etc does not bypass an allow
// for /tmp. If symlink resolution diverges (common on macOS where /tmp
// resolves to /private/tmp but a non-existent /tmp/foo cannot be resolved),
// the literal Clean'd form is tried as a fallback so neither side has to
// exist for the comparison to succeed.
func pathUnderOrEqual(path, prefix string) bool {
	np := normalizePath(path)
	npref := normalizePath(prefix)
	if matchesUnder(np, npref) {
		return true
	}
	litPath := filepath.Clean(path)
	litPref := filepath.Clean(prefix)
	if litPath != np || litPref != npref {
		if matchesUnder(litPath, litPref) {
			return true
		}
	}
	return false
}

func matchesUnder(p, pref string) bool {
	if p == pref {
		return true
	}
	// normalizePath already Clean()'s both sides, so pref has no trailing
	// separator. The "/" case is special-cased so it still matches /etc etc.
	if pref == string(filepath.Separator) {
		return strings.HasPrefix(p, pref)
	}
	return strings.HasPrefix(p, pref+string(filepath.Separator))
}

// normalizePath expands ~, resolves .., and best-effort resolves symlinks.
// Symlink resolution is allowed to fail (path may not exist) — in that case
// we fall back to filepath.Clean's result so normalization never errors out
// and turns a benign command into a deny.
func normalizePath(p string) string {
	if p == "" {
		return p
	}
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgate: cannot expand ~ (%v); rule using %q may not match\n", err, p)
		} else {
			if p == "~" {
				p = home
			} else {
				p = filepath.Join(home, p[2:])
			}
		}
	}
	p = filepath.Clean(p)
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		p = resolved
	}
	return p
}
