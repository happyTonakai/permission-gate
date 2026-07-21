package verdict

import "fmt"

type Level int

const (
	LevelAllow Level = iota
	LevelDeny
	LevelAsk
)

func (l Level) String() string {
	switch l {
	case LevelAllow:
		return "allow"
	case LevelDeny:
		return "deny"
	case LevelAsk:
		return "ask"
	default:
		return "unknown"
	}
}

type Verdict struct {
	Level   Level  `json:"level"`
	Reason  string `json:"reason"`
	Matched string `json:"matched"`
	// UserMsg is the user-authored hint from a deny rule's `msg` field.
	// It travels through the JSON output so the agent-side hook (pi
	// extension, claude PermissionRequest hook, opencode plugin) can
	// substitute it for the synthetic `Reason` in the agent-visible
	// message — see cmd/pgate/hooks.go for the exact rendering. Reason
	// is kept unchanged because it still drives the local log line and
	// is what a human reads when debugging why a command was blocked.
	// Omitted on allow/ask verdicts and on deny verdicts whose spec
	// didn't set msg.
	UserMsg string `json:"user_msg,omitempty"`
}

func Allow(reason, matched string) Verdict {
	return Verdict{Level: LevelAllow, Reason: reason, Matched: matched}
}

func Deny(reason, matched string) Verdict {
	return Verdict{Level: LevelDeny, Reason: reason, Matched: matched}
}

func Ask(reason string) Verdict {
	return Verdict{Level: LevelAsk, Reason: reason}
}

func (v Verdict) String() string {
	s := v.Level.String()
	if v.Reason != "" {
		s += ": " + v.Reason
	}
	if v.UserMsg != "" {
		// Render the user-authored hint on its own indented line so it
		// stays visible in `pgate check --detail` and other non-JSON
		// output paths — otherwise users authoring msg fields can't see
		// what the agent will read without falling back to --json.
		s += "\n    msg: " + v.UserMsg
	}
	return s
}

// SegmentResult holds the verdict for one command segment in a pipeline/chain.
type SegmentResult struct {
	Command string   `json:"command"` // canonical form of the command
	Tokens  []string `json:"tokens"`  // tokenized command
	Verdict Verdict  `json:"verdict"`
}

type Result struct {
	RawCommand string          `json:"raw_command"`
	Segments   []SegmentResult `json:"segments"`
	Final      Verdict         `json:"final"`
}

func (r Result) String() string {
	s := fmt.Sprintf("Final: %s\n", r.Final)
	for _, seg := range r.Segments {
		s += fmt.Sprintf("  [%s] %s", seg.Verdict.Level, seg.Command)
		if seg.Verdict.Matched != "" {
			s += fmt.Sprintf(" (matched: %s)", seg.Verdict.Matched)
		}
		s += "\n"
	}
	return s
}
