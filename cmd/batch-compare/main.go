package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/happyTonakai/permission-gate/internal/builtin"
	"github.com/happyTonakai/permission-gate/internal/config"
	"github.com/happyTonakai/permission-gate/internal/rules"
	"github.com/happyTonakai/permission-gate/internal/verdict"
)

type LogEntry struct {
	Ts      string `json:"ts"`
	Result  string `json:"result"`
	Command string `json:"command"`
}

type runStats struct {
	agree    int
	disagree int
	allow    int
	deny     int
	ask      int
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <logfile>\n", os.Args[0])
		os.Exit(1)
	}

	entries := loadLogFile(os.Args[1])
	unique := dedupe(entries)
	fmt.Printf("Total entries: %d, unique commands: %d\n\n", len(entries), len(unique))

	cfg := &config.Config{}
	engine, err := rules.New(cfg, config.MergePrepend, builtin.Allow(), builtin.Deny(), builtin.Ask(), builtin.DenyFlags())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	stats := evaluateAll(engine, unique)
	printSummary(stats, len(unique))
}

// loadLogFile reads a newline-delimited JSON log and returns the parsed
// entries. Malformed lines and empty commands are silently skipped.
func loadLogFile(path string) []LogEntry {
	data, err := os.ReadFile(path)
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
	return entries
}

// dedupe returns entries in first-occurrence order with duplicate
// commands removed.
func dedupe(entries []LogEntry) []LogEntry {
	seen := make(map[string]bool)
	var unique []LogEntry
	for _, e := range entries {
		if seen[e.Command] {
			continue
		}
		seen[e.Command] = true
		unique = append(unique, e)
	}
	return unique
}

// evaluateAll runs the engine over every unique entry, prints a one-line
// trace for each disagreement, and tallies per-level counts.
func evaluateAll(engine *rules.Engine, entries []LogEntry) runStats {
	var stats runStats
	for _, entry := range entries {
		result := engine.Evaluate(entry.Command)
		pgVerdict := result.Final.Level.String()
		tallyLevel(&stats, result.Final.Level)
		if pgVerdict == entry.Result {
			stats.agree++
			continue
		}
		stats.disagree++
		printDisagreement(entry, result, pgVerdict)
	}
	return stats
}

// tallyLevel increments the matching level counter. An unknown level
// (e.g. a future addition to the verdict package) is reported to stderr
// and skipped so the summary stays accurate for the levels we know.
func tallyLevel(s *runStats, level verdict.Level) {
	switch level {
	case verdict.LevelAllow:
		s.allow++
	case verdict.LevelDeny:
		s.deny++
	case verdict.LevelAsk:
		s.ask++
	default:
		fmt.Fprintf(os.Stderr, "warning: unexpected verdict level %d (%s)\n", level, level)
	}
}

// printDisagreement emits a one-line summary plus per-segment detail for
// commands where the engine's verdict differs from the logged result.
func printDisagreement(entry LogEntry, result *verdict.Result, pgVerdict string) {
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

// printSummary writes the final tally to stdout.
func printSummary(s runStats, total int) {
	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Agree:     %d\n", s.agree)
	fmt.Printf("Disagree:  %d\n", s.disagree)
	fmt.Printf("PG allow:  %d\n", s.allow)
	fmt.Printf("PG deny:   %d\n", s.deny)
	fmt.Printf("PG ask:    %d\n", s.ask)
	fmt.Printf("Total:     %d\n", total)
}
