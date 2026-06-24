package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/happyTonakai/permission-gate/internal/builtin"
	"github.com/happyTonakai/permission-gate/internal/config"
	"github.com/happyTonakai/permission-gate/internal/rules"
	"github.com/happyTonakai/permission-gate/internal/verdict"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "check":
		runCheck(os.Args[2:])
	case "init":
		runInit()
	case "hook":
		runHook(os.Args[2:])
	case "version":
		fmt.Println("permission-gate v0.1.0")
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Permission Gate — AST-based bash command permission checker.

Usage:
  pgate check [flags] <command>    Check a command against the rules
  pgate init                       Create default config file
  pgate hook install <target>      Install hook (claude-code | opencode | pi)
  pgate hook uninstall <target>    Uninstall hook
  pgate version                    Show version

Flags for "check":
  --json       Output result as JSON
  --detail     Show per-segment analysis
`)
}

func runInit() {
	path, err := config.InitConfig()
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			fmt.Println("Config already exists at", path)
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	fmt.Println("Created config at", path)
}

func runCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "Output result as JSON")
	detail := fs.Bool("detail", false, "Show per-segment analysis")
	fs.Parse(args)

	cmd := strings.Join(fs.Args(), " ")
	if cmd == "" {
		// Read from stdin if no command provided
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			data, _ := io.ReadAll(os.Stdin)
			cmd = strings.TrimSpace(string(data))
		}
	}
	if cmd == "" {
		fmt.Fprintf(os.Stderr, "Usage: pgate check [--json] [--detail] <command>\n")
		os.Exit(1)
	}

	cwd, _ := os.Getwd()
	cfg, mode, err := config.ResolveConfig(cwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	engine, err := rules.New(cfg, mode, builtin.Allow(), builtin.Deny(), builtin.Ask(), builtin.DenyFlags())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error building rule engine: %v\n", err)
		os.Exit(1)
	}
	result := engine.Evaluate(cmd)

	if *jsonOutput {
		printJSON(result)
		return
	}

	if *detail {
		fmt.Print(result)
		return
	}

	// Simple output
	switch result.Final.Level {
	case verdict.LevelAllow:
		fmt.Println("allow")
	case verdict.LevelDeny:
		fmt.Println("deny")
		if result.Final.Reason != "" {
			fmt.Fprintln(os.Stderr, "Reason:", result.Final.Reason)
		}
		os.Exit(1)
	case verdict.LevelAsk:
		fmt.Println("ask")
		if result.Final.Reason != "" {
			fmt.Fprintln(os.Stderr, "Reason:", result.Final.Reason)
		}
	}
}

func runHook(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: pgate hook install|uninstall <target>\n")
		fmt.Fprintf(os.Stderr, "Targets: claude-code, opencode, pi\n")
		os.Exit(1)
	}

	switch args[0] {
	case "install":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: pgate hook install <target>")
			fmt.Fprintln(os.Stderr, "Targets: claude-code, opencode, pi")
			os.Exit(1)
		}
		if err := installHook(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Installed permission-gate hook for %s\n", args[1])

	case "uninstall":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: pgate hook uninstall <target>")
			fmt.Fprintln(os.Stderr, "Targets: claude-code, opencode, pi")
			os.Exit(1)
		}
		if err := uninstallHook(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Removed permission-gate hook for %s\n", args[1])

	case "claude-request":
		handleClaudeRequest()

	default:
		fmt.Fprintf(os.Stderr, "Unknown hook action: %s\n", args[0])
		os.Exit(1)
	}
}

// ─── Claude Code hook handler ─────────────────────────────────

type claudeLogEntry struct {
	TS      string `json:"ts"`
	Level   string `json:"level"`
	Command string `json:"command"`
	Reason  string `json:"reason,omitempty"`
}

func logClaudeDecision(level, command, reason string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	logDir := filepath.Join(home, ".claude", "hooks")
	os.MkdirAll(logDir, 0755)
	logFile := filepath.Join(logDir, "permission-gate."+time.Now().Format("20060102")+".log")

	entry := claudeLogEntry{
		TS:      time.Now().Format(time.RFC3339),
		Level:   level,
		Command: command,
		Reason:  reason,
	}
	data, _ := json.Marshal(entry)
	os.WriteFile(logFile, append(data, '\n'), 0644)

	// Clean logs older than 7 days
	cleanupLogs(logDir, "permission-gate.", 7)
}

func cleanupLogs(dir, prefix string, keepDays int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -keepDays)
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

func handleClaudeRequest() {
	var req struct {
		ToolName  string `json:"tool_name"`
		ToolInput struct {
			Command string `json:"command"`
		} `json:"tool_input"`
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(0)
	}
	if err := json.Unmarshal(data, &req); err != nil {
		os.Exit(0)
	}

	if req.ToolName != "Bash" || req.ToolInput.Command == "" {
		os.Exit(0)
	}

	cwd, _ := os.Getwd()
	cfg, mode, err := config.ResolveConfig(cwd)
	if err != nil {
		os.Exit(0)
	}

	engine, err := rules.New(cfg, mode, builtin.Allow(), builtin.Deny(), builtin.Ask(), builtin.DenyFlags())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(0)
	}
	result := engine.Evaluate(req.ToolInput.Command)

	behavior := verdictLevelToClaude(result.Final.Level)
	logClaudeDecision(behavior, req.ToolInput.Command, result.Final.Reason)

	resp := claudeHookResponse{
		HookSpecificOutput: claudeHookOutput{
			HookEventName: "PermissionRequest",
			Decision: claudeHookDecision{
				Behavior: behavior,
				Message:  result.Final.Reason,
			},
		},
	}
	json.NewEncoder(os.Stdout).Encode(resp)
}

type claudeHookResponse struct {
	HookSpecificOutput claudeHookOutput `json:"hookSpecificOutput"`
}

type claudeHookOutput struct {
	HookEventName string             `json:"hookEventName"`
	Decision      claudeHookDecision `json:"decision"`
}

type claudeHookDecision struct {
	Behavior string `json:"behavior"`
	Message  string `json:"message,omitempty"`
}

func verdictLevelToClaude(l verdict.Level) string {
	switch l {
	case verdict.LevelAllow:
		return "allow"
	case verdict.LevelDeny:
		return "deny"
	default:
		return "ask"
	}
}

func printJSON(result *verdict.Result) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(result)
}
