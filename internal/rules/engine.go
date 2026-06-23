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
}

// New creates a rule engine from config plus built-in rules.
func New(cfg *config.Config, builtinAllow, builtinDeny, builtinAsk []string, builtinDenyFlags map[string][]string) *Engine {
	e := &Engine{
		denyFlags: make(map[string][]string),
	}

	// Merge built-in + user-config rules
	allAllow := append(builtinAllow, cfg.Allow.Commands...)
	allDeny := append(builtinDeny, cfg.Deny.Commands...)
	allAsk := append(builtinAsk, cfg.Ask.Commands...)

	for _, cmd := range allAllow {
		e.allowPatterns = append(e.allowPatterns, pattern{tokens: splitRule(cmd), raw: cmd})
	}
	for _, cmd := range allDeny {
		e.denyPatterns = append(e.denyPatterns, pattern{tokens: splitRule(cmd), raw: cmd})
	}
	for _, cmd := range allAsk {
		e.askPatterns = append(e.askPatterns, pattern{tokens: splitRule(cmd), raw: cmd})
	}

	for cmd, flags := range cfg.Deny.Flags {
	builtinDenyFlags[cmd] = append(builtinDenyFlags[cmd], flags...)
		}
	for cmd, flags := range builtinDenyFlags {
		e.denyFlags[cmd] = append(e.denyFlags[cmd], flags...)
	}

	return e
}

// Check evaluates a single extracted command against the rules.
func (e *Engine) Check(cmd analyze.ExtractedCommand) verdict.Verdict {
	// 1. Check deny patterns
	for _, p := range e.denyPatterns {
		if cmd.IsPrefixMatch(p.tokens) {
			return verdict.Deny("command on deny list", p.raw)
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

	// 3. Check allow patterns
	for _, p := range e.allowPatterns {
		if cmd.IsPrefixMatch(p.tokens) {
			return verdict.Allow("command on allow list", p.raw)
		}
	}

	// 4. Check ask patterns
	for _, p := range e.askPatterns {
		if cmd.IsPrefixMatch(p.tokens) {
			return verdict.Ask("command on ask list")
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
		// Parse error — deny to be safe
		result.Final = verdict.Deny("failed to parse command: "+err.Error(), "")
		return result
	}

	if len(commands) == 0 {
		result.Final = verdict.Allow("no commands to execute", "")
		return result
	}

	anyDeny := false
	anyAsk := false

	for _, cmd := range commands {
		v := e.Check(cmd)
		result.Segments = append(result.Segments, verdict.SegmentResult{
			Command: cmd.Raw,
			Tokens:  cmd.Tokens,
			Verdict: v,
		})
		switch v.Level {
		case verdict.LevelDeny:
			anyDeny = true
		case verdict.LevelAsk:
			anyAsk = true
		}
	}

	switch {
	case anyDeny:
		result.Final = verdict.Deny("one or more commands are denied", "")
	case !anyAsk:
		result.Final = verdict.Allow("all commands are allowed", "")
	default:
		result.Final = verdict.Ask("some commands need confirmation")
	}

	return result
}

func splitRule(rule string) []string {
	return strings.Fields(rule)
}


