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
	return s
}

// SegmentResult holds the verdict for one command segment in a pipeline/chain.
type SegmentResult struct {
	Command string  `json:"command"`  // canonical form of the command
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
