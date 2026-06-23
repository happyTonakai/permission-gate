package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"io"
	"strings"

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
  pgate hook install <target>      Install hook (claude-code | opencode | pi-agent)
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
	cfg, _, err := config.ResolveConfig(cwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	engine := rules.New(cfg, builtin.Allow(), builtin.Deny(), builtin.Ask(), builtin.DenyFlags())
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
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: pgate hook install|uninstall <target>\n")
		fmt.Fprintf(os.Stderr, "Targets: claude-code, opencode, pi-agent\n")
		os.Exit(1)
	}

	action := args[0]
	target := args[1]

	switch action {
	case "install":
		if err := installHook(target); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Installed permission-gate hook for %s\n", target)
	case "uninstall":
		if err := uninstallHook(target); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Removed permission-gate hook for %s\n", target)
	default:
		fmt.Fprintf(os.Stderr, "Unknown action: %s (use install or uninstall)\n", action)
		os.Exit(1)
	}
}

func printJSON(result *verdict.Result) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(result)
}
