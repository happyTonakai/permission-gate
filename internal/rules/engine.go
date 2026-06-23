package rules

import (
	"strings"

	"github.com/happyTonakai/permission-gate/internal/analyze"
	"github.com/happyTonakai/permission-gate/internal/config"
	"github.com/happyTonakai/permission-gate/internal/verdict"
)

// Engine evaluates commands against allow/deny/ask rules.
type Engine struct {
	allowPatterns []pattern
	denyPatterns  []pattern
	askPatterns   []pattern
	// flagRules: cmd prefix → set of denied flags
	denyFlags map[string][]string
}

type pattern struct {
	tokens []string // split rule, e.g. "git log" → ["git", "log"]
	raw    string   // original rule text
	source string   // "builtin", "global", "project"
}

// New creates a rule engine from config plus built-in rules.
func New(cfg *config.Config, builtinAllow, builtinDeny, builtinAsk []string, builtinDenyFlags map[string][]string) *Engine {
	e := &Engine{
		denyFlags: make(map[string][]string),
	}

	// Built-in patterns
	addPatterns(&e.allowPatterns, builtinAllow, "builtin")
	addPatterns(&e.denyPatterns, builtinDeny, "builtin")
	addPatterns(&e.askPatterns, builtinAsk, "builtin")

	// Global config patterns
	addPatterns(&e.allowPatterns, cfg.GlobalRaw.Allow.Commands, "global")
	addPatterns(&e.denyPatterns, cfg.GlobalRaw.Deny.Commands, "global")
	addPatterns(&e.askPatterns, cfg.GlobalRaw.Ask.Commands, "global")

	// Project config patterns
	addPatterns(&e.allowPatterns, cfg.ProjectRaw.Allow.Commands, "project")
	addPatterns(&e.denyPatterns, cfg.ProjectRaw.Deny.Commands, "project")
	addPatterns(&e.askPatterns, cfg.ProjectRaw.Ask.Commands, "project")

	for cmd, flags := range cfg.Deny.Flags {
		builtinDenyFlags[cmd] = append(builtinDenyFlags[cmd], flags...)
	}
	for cmd, flags := range builtinDenyFlags {
		e.denyFlags[cmd] = append(e.denyFlags[cmd], flags...)
	}

	return e
}

func addPatterns(dst *[]pattern, cmds []string, source string) {
	for _, cmd := range cmds {
		*dst = append(*dst, pattern{tokens: splitRule(cmd), raw: cmd, source: source})
	}
}

// Check evaluates a single extracted command against the rules.
func (e *Engine) Check(cmd analyze.ExtractedCommand) verdict.Verdict {
	// 1. Check deny patterns
	for _, p := range e.denyPatterns {
		if cmd.Match(p.tokens) {
			return verdict.Deny(p.source+" deny: "+p.raw, p.raw)
		}
	}

	// 2. Check deny flags (for commands that are otherwise allowed)
	if flags, ok := e.denyFlags[cmd.Name()]; ok {
		for _, flag := range flags {
			if cmd.HasFlag(flag) {
				return verdict.Deny("dangerous flag: "+flag, cmd.Name()+":"+flag)
			}
		}
	}

	// 3. Check ask patterns (before allow, so explicit ask overrides broad allow)
	for _, p := range e.askPatterns {
		if cmd.Match(p.tokens) {
			return verdict.Ask(p.source + " ask: " + p.raw)
		}
	}

	// 4. Check allow patterns
	for _, p := range e.allowPatterns {
		if cmd.Match(p.tokens) {
			return verdict.Allow(p.source+" allow: "+p.raw, p.raw)
		}
	}

	// 5. Unknown → ask
	return verdict.Ask("unknown command, requires confirmation")
}

// Evaluate parses a raw command and returns the result for all segments.
func (e *Engine) Evaluate(rawCmd string) *verdict.Result {
	result := &verdict.Result{RawCommand: rawCmd}

	commands, err := analyze.ExtractCommands(rawCmd)
	if err != nil {
		// Parse error — ask so the user can confirm manually.
		// We never silently deny: an unparseable shell is not necessarily
		// dangerous, and the user knows what they meant to run.
		result.Final = verdict.Ask("failed to parse command: "+err.Error())
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

func splitRule(rule string) []string {
	return strings.Fields(rule)
}


