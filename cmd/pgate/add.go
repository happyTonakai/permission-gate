package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/happyTonakai/permission-gate/internal/config"
)

// runAdd implements
// `pgate add [--action=allow|ask|deny] [--scope=user|project] <command>...`.
//
// The spec is built by joining every positional argument with a single
// space — so callers can pass either a single quoted string
// (`pgate add "docker compose up"`) or several bare tokens
// (`pgate add docker compose up`); both produce the same stored spec.
//
// The `--action` flag selects which section the spec is appended to:
// `--action=allow` (the default — matches the pre-flag behavior) writes
// to `[allow].commands`, `--action=ask` writes to `[ask].commands`, and
// `--action=deny` writes to `[deny].commands`. The same spec is therefore
// routable into the permission tier you want for it.
//
// Security note: `pgate add` itself is classified as ask in the built-in
// rules, so an agent that wants to grant itself a permission still has
// to get the user to approve the `pgate add …` invocation first
// regardless of which `--action` value it passes. The human in the loop
// sees one confirmation prompt, then the entry is added; future
// invocations of the added command use the rule without prompting.
//
// Scope resolution matches the read path so a write actually influences
// the next check:
//
//	--scope=user    → PERMISSION_GATE_CONFIG or ~/.config/permission-gate/config.toml
//	--scope=project → PERMISSION_GATE_PROJECT_CONFIG or <cwd>/.permission-gate.toml
func runAdd(args []string) {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	scopeFlag := fs.String("scope", "user", "Config scope to write to: user|project")
	actionFlag := fs.String("action", "allow",
		"Which section to append to: allow|ask|deny")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: pgate add [--action=allow|ask|deny] [--scope=user|project] <command>...\n\n")
		fmt.Fprintf(os.Stderr, "Append <command> to the chosen section of the chosen config file.\n")
		fmt.Fprintf(os.Stderr, "All positional args are joined with a single space, so:\n")
		fmt.Fprintf(os.Stderr, "  pgate add docker compose up\n")
		fmt.Fprintf(os.Stderr, "  pgate add \"docker compose up\"\n")
		fmt.Fprintf(os.Stderr, "both store the spec \"docker compose up\".\n\n")
		fmt.Fprintf(os.Stderr, "Action (which tier the entry belongs to):\n")
		fmt.Fprintf(os.Stderr, "  allow  (default) [allow].commands — auto-pass\n")
		fmt.Fprintf(os.Stderr, "  ask              [ask].commands   — prompt the user\n")
		fmt.Fprintf(os.Stderr, "  deny             [deny].commands  — auto-block\n\n")
		fmt.Fprintf(os.Stderr, "Scope:\n")
		fmt.Fprintf(os.Stderr, "  user    (default) ~/.config/permission-gate/config.toml\n")
		fmt.Fprintf(os.Stderr, "  project           <cwd>/.permission-gate.toml\n\n")
		fmt.Fprintf(os.Stderr, "Note: \"pgate add\" itself is gated as ask, so an agent\n")
		fmt.Fprintf(os.Stderr, "cannot grant itself permissions without user approval.\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	positional := fs.Args()
	if len(positional) == 0 {
		fs.Usage()
		os.Exit(1)
	}
	spec := strings.Join(positional, " ")
	if strings.TrimSpace(spec) == "" {
		fmt.Fprintln(os.Stderr, "Error: command spec cannot be empty")
		os.Exit(1)
	}

	scope, err := config.ParseScope(*scopeFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	action, err := config.ParseAction(*actionFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	path, added, err := config.AddCommand(spec, action, scope)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if !added {
		fmt.Printf("Already in %s %s list: %q (%s)\n", scope, action, spec, path)
		return
	}
	fmt.Printf("Added %q to %s %s list at %s\n", spec, scope, action, path)
	fmt.Println("The next command check will use this rule (no restart required).")
}
