package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

type TomlCommand struct {
	Name        string           `toml:"name"`
	Aliases     []string         `toml:"aliases"`
	Level       string           `toml:"level"`
	Standalone  []string         `toml:"standalone"`
	Valued      []string         `toml:"valued"`
	BareFlags   []string         `toml:"bare_flags"`
	SubCommands []TomlSubCommand `toml:"sub"`
}

type TomlSubCommand struct {
	Name       string           `toml:"name"`
	Level      string           `toml:"level"`
	Bare       *bool            `toml:"bare"`
	Standalone []string         `toml:"standalone"`
	Valued     []string         `toml:"valued"`
	AllowAll   *bool            `toml:"allow_all"`
	Delegate   string           `toml:"delegate"`
	SubSub     []TomlSubCommand `toml:"sub"`
}

func main() {
	const root = "_ref-safe-chains/commands"
	const outPath = "internal/builtin/generated_commands.go"

	byCategory := make(map[string][]string) // category → commands
	if err := collectByCategory(root, byCategory); err != nil {
		fmt.Fprintf(os.Stderr, "walk error: %v\n", err)
		os.Exit(1)
	}

	allCmds, categories := dedupeByCategory(byCategory)
	if err := writeGenerated(outPath, allCmds); err != nil {
		fmt.Fprintf(os.Stderr, "write error: %v\n", err)
		os.Exit(1)
	}

	printStats(outPath, allCmds, categories, byCategory)
}

// collectByCategory walks the root directory and accumulates commands per
// category by parsing every non-SAMPLE TOML file.
func collectByCategory(root string, byCategory map[string][]string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if !shouldProcess(err, info) {
			return nil
		}
		category := categoryOf(root, path)
		return processTomlFile(path, category, byCategory)
	})
}

// shouldProcess reports whether a walk entry is a real TOML data file we
// should read (excludes directories, non-TOML files, and the SAMPLE stub).
func shouldProcess(err error, info os.FileInfo) bool {
	if err != nil || info.IsDir() {
		return false
	}
	if !strings.HasSuffix(info.Name(), ".toml") {
		return false
	}
	if info.Name() == "SAMPLE.toml" {
		return false
	}
	return true
}

// categoryOf returns the directory of path relative to root, or "root" if
// the file lives directly under root.
func categoryOf(root, path string) string {
	rel, err := filepath.Rel(root, filepath.Dir(path))
	if err != nil || rel == "." {
		return "root"
	}
	return rel
}

// processTomlFile reads and parses a single TOML file, then routes each
// command to the per-category allow list. Read and decode errors are
// reported to stderr and treated as a skip (returns nil).
func processTomlFile(path, category string, byCategory map[string][]string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  skip %s: %v\n", filepath.Base(path), err)
		return nil
	}
	var doc struct {
		Commands []TomlCommand `toml:"command"`
	}
	if err := toml.Unmarshal(data, &doc); err != nil {
		fmt.Fprintf(os.Stderr, "  skip %s: %v\n", filepath.Base(path), err)
		return nil
	}
	for _, cmd := range doc.Commands {
		addCommand(cmd, category, byCategory)
	}
	return nil
}

// addCommand fans a single TOML command out to one or more allow patterns
// under category, walking the command's subcommands if any.
func addCommand(cmd TomlCommand, category string, byCategory map[string][]string) {
	names := append([]string{cmd.Name}, cmd.Aliases...)
	if cmd.Name == "" {
		return
	}
	for _, name := range names {
		if !isUsableName(name) {
			continue
		}
		if len(cmd.SubCommands) > 0 {
			addCommandWithSubs(name, cmd.SubCommands, category, byCategory)
		} else {
			addFlatCommand(name, cmd.Level, category, byCategory)
		}
	}
}

// isUsableName drops npm-scoped names, paths, and trivial operators
// that we don't want to emit as allow patterns.
func isUsableName(name string) bool {
	if strings.HasPrefix(name, "@") || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	if name == ":" || name == "." {
		return false
	}
	return true
}

// addCommandWithSubs emits the base command name and one allow pattern per
// usable subcommand (and sub-subcommand). Delegate, AllowAll, and
// SafeWrite entries are handled as documented in the generated list.
func addCommandWithSubs(name string, subs []TomlSubCommand, category string, byCategory map[string][]string) {
	byCategory[category] = append(byCategory[category], name)
	for _, sub := range subs {
		fullName := name + " " + sub.Name
		if sub.Delegate != "" {
			continue
		}
		if sub.AllowAll != nil && *sub.AllowAll {
			byCategory[category] = append(byCategory[category], fullName+" *")
			continue
		}
		if sub.Level == "SafeWrite" {
			continue
		}
		byCategory[category] = append(byCategory[category], fullName)
		for _, subsub := range sub.SubSub {
			byCategory[category] = append(byCategory[category], fullName+" "+subsub.Name)
		}
	}
}

// addFlatCommand emits a flat (no-subcommand) allow pattern when the
// command's level is empty, "Inert", or "SafeRead".
func addFlatCommand(name, level string, category string, byCategory map[string][]string) {
	if level == "" || level == "Inert" || level == "SafeRead" {
		byCategory[category] = append(byCategory[category], name)
	}
}

// dedupeByCategory flattens byCategory into a single sorted-unique list
// while preserving the per-category sort applied in place. The returned
// categories slice is sorted alphabetically.
func dedupeByCategory(byCategory map[string][]string) (allCmds, categories []string) {
	for cat := range byCategory {
		categories = append(categories, cat)
	}
	sort.Strings(categories)

	seen := make(map[string]bool)
	for _, cat := range categories {
		cmds := byCategory[cat]
		sort.Strings(cmds)
		for _, c := range cmds {
			if seen[c] {
				continue
			}
			seen[c] = true
			allCmds = append(allCmds, c)
		}
	}
	return allCmds, categories
}

// writeGenerated emits the generatedAllow() function literal to outPath.
func writeGenerated(outPath string, allCmds []string) error {
	var sb strings.Builder
	sb.WriteString("// Code generated by internal/builtin/cmd/convert.go; DO NOT EDIT.\n")
	sb.WriteString("package builtin\n\n")
	sb.WriteString("func generatedAllow() []string {\n")
	sb.WriteString("\treturn []string{\n")
	for _, c := range allCmds {
		fmt.Fprintf(&sb, "\t\t%q,\n", c)
	}
	sb.WriteString("\t}\n")
	sb.WriteString("}\n")
	return os.WriteFile(outPath, []byte(sb.String()), 0o644)
}

// printStats writes a small summary of the conversion to stdout.
func printStats(outPath string, allCmds, categories []string, byCategory map[string][]string) {
	fmt.Printf("Written to %s\n", outPath)
	fmt.Printf("  Total patterns: %d\n", len(allCmds))
	fmt.Printf("  Categories:     %d\n", len(categories))
	for _, cat := range categories {
		fmt.Printf("    %-20s %3d\n", cat, len(byCategory[cat]))
	}
}
