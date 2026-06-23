package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/happyTonakai/permission-gate/internal/builtin"
	"github.com/happyTonakai/permission-gate/internal/config"
	"github.com/happyTonakai/permission-gate/internal/rules"
)

type LogEntry struct {
	Ts      string `json:"ts"`
	Result  string `json:"result"`
	Command string `json:"command"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <logfile>\n", os.Args[0])
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}

	var entries []LogEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e LogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		if e.Command == "" {
			continue
		}
		entries = append(entries, e)
	}

	seen := make(map[string]bool)
	var unique []LogEntry
	for _, e := range entries {
		if !seen[e.Command] {
			seen[e.Command] = true
			unique = append(unique, e)
		}
	}

	fmt.Printf("Total entries: %d, unique commands: %d\n\n", len(entries), len(unique))

	cfg := &config.Config{}
	engine := rules.New(cfg, builtin.Allow(), builtin.Deny(), builtin.Ask(), builtin.DenyFlags())

	agree := 0
	disagree := 0
	pgDeny := 0
	pgAsk := 0
	pgAllow := 0

	for _, entry := range unique {
		result := engine.Evaluate(entry.Command)
		pgVerdict := result.Final.Level.String()

		switch result.Final.Level {
		case 0:
			pgAllow++
		case 1:
			pgDeny++
		case 2:
			pgAsk++
		}

		if pgVerdict == entry.Result {
			agree++
		} else {
			disagree++
			shortCmd := entry.Command
			if len(shortCmd) > 120 {
				shortCmd = shortCmd[:120] + "..."
			}
			shortCmd = strings.ReplaceAll(shortCmd, "\n", "\\n")
			fmt.Printf("✗ pi=%-6s pg=%-6s | %s\n", entry.Result, pgVerdict, shortCmd)
			for _, s := range result.Segments {
				m := ""
				if s.Verdict.Matched != "" {
					m = fmt.Sprintf(" (matched: %s)", s.Verdict.Matched)
				}
				fmt.Printf("    [%s] %s%s\n", s.Verdict.Level, s.Command, m)
			}
		}
	}

	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Agree:     %d\n", agree)
	fmt.Printf("Disagree:  %d\n", disagree)
	fmt.Printf("PG allow:  %d\n", pgAllow)
	fmt.Printf("PG deny:   %d\n", pgDeny)
	fmt.Printf("PG ask:    %d\n", pgAsk)
	fmt.Printf("Total:     %d\n", agree+disagree)

	_ = config.DefaultConfig
}
