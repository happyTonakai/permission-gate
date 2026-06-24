package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

type MergeMode string

const (
	MergePrepend   MergeMode = "prepend"
	MergeAppend    MergeMode = "append"
	MergeOverwrite MergeMode = "overwrite"
)

// CommandSpec is one rule entry in an allow/deny/ask list. It can be specified
// in TOML as either a bare string ("git log") or an inline table:
//
//	commands = [
//	  "rg",
//	  { cmd = "rm", include_flags = ["-f", "-rf", "-r"],
//	    include_args = ["/tmp", "/private/tmp"] },
//	]
//
// All refinement fields are optional. Matching flow (all must hold for a spec
// to match a command):
//
//  1. Cmd prefix-matches the leading tokens of the command.
//  2. No flag in ExcludeFlags appears in the command.
//  3. At least one flag in IncludeFlags appears (only checked when IncludeFlags
//     is non-empty).
//  4. No non-flag arg starts with any ExcludeArgs prefix.
//  5. Every non-flag arg starts with some IncludeArgs prefix (only checked
//     when IncludeArgs is non-empty).
//
// Steps 2+4 (excludes) are evaluated before 3+5 (includes): exclude wins per
// field. Short option bundles are expanded on both sides when checking flag
// constraints (-rf matches -r, -f, -rf, -fr, ...). POSIX `--` terminates flag
// scanning; everything after it is treated as a positional argument.
type CommandSpec struct {
	Cmd          string
	IncludeFlags []string
	ExcludeFlags []string
	IncludeArgs  []string
	ExcludeArgs  []string
}

// RawRules is the on-disk shape of an allow/deny/ask block. Commands are kept
// as []any because TOML entries may be either strings or inline tables; they
// are normalized to []CommandSpec via Specs().
type RawRules struct {
	Commands []any               `toml:"commands,omitempty"`
	Flags    map[string][]string `toml:"flags,omitempty"`
}

// Specs normalizes raw command entries into []CommandSpec.
func (r RawRules) Specs() ([]CommandSpec, error) {
	out := make([]CommandSpec, 0, len(r.Commands))
	for i, c := range r.Commands {
		s, err := parseCommandSpec(c)
		if err != nil {
			return nil, fmt.Errorf("commands[%d]: %w", i, err)
		}
		out = append(out, s)
	}
	return out, nil
}

func parseCommandSpec(v any) (CommandSpec, error) {
	switch x := v.(type) {
	case string:
		return CommandSpec{Cmd: x}, nil
	case map[string]any:
		s := CommandSpec{}
		if cmd, ok := x["cmd"].(string); ok {
			s.Cmd = cmd
		} else {
			return s, fmt.Errorf("missing string field 'cmd' (got %T)", x["cmd"])
		}
		var err error
		if s.IncludeFlags, err = toStringSlice("include_flags", x["include_flags"]); err != nil {
			return s, err
		}
		if s.ExcludeFlags, err = toStringSlice("exclude_flags", x["exclude_flags"]); err != nil {
			return s, err
		}
		if s.IncludeArgs, err = toStringSlice("include_args", x["include_args"]); err != nil {
			return s, err
		}
		if s.ExcludeArgs, err = toStringSlice("exclude_args", x["exclude_args"]); err != nil {
			return s, err
		}
		return s, nil
	default:
		return CommandSpec{}, fmt.Errorf("unsupported command spec type %T (want string or inline table)", v)
	}
}

// toStringSlice extracts a string array from an inline-table field. Missing
// fields return (nil, nil). Wrong-typed entries (e.g. an integer inside an
// otherwise-string array) surface as an error so the user's misconfiguration
// is reported instead of being silently dropped.
func toStringSlice(field string, v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected array of strings, got %T", field, v)
	}
	out := make([]string, 0, len(arr))
	for i, x := range arr {
		s, ok := x.(string)
		if !ok {
			return nil, fmt.Errorf("%s[%d]: expected string, got %T", field, i, x)
		}
		out = append(out, s)
	}
	return out, nil
}

// CommandRules holds the resolved rules after merging global + project.
// Commands are []CommandSpec (already normalized from RawRules).
type CommandRules struct {
	Commands []CommandSpec
	Flags    map[string][]string
}

func (r CommandRules) IsZero() bool {
	return len(r.Commands) == 0 && len(r.Flags) == 0
}

// RawConfig is the on-disk TOML structure for one config file.
type RawConfig struct {
	Allow     RawRules  `toml:"allow"`
	Deny      RawRules  `toml:"deny"`
	Ask       RawRules  `toml:"ask"`
	MergeMode MergeMode `toml:"merge_mode,omitempty"`
}

// Config is the resolved configuration after merging. The merged Commands /
// Flags slices on Allow/Deny/Ask are convenience views; the rule engine loads
// patterns from GlobalRaw / ProjectRaw directly so it can attribute each rule
// to its source.
type Config struct {
	Allow CommandRules
	Deny  CommandRules
	Ask   CommandRules

	GlobalRaw  RawConfig
	ProjectRaw RawConfig
}

// ProjectOverride holds project-level settings.
type ProjectOverride struct {
	Allow     CommandRules
	Deny      CommandRules
	Ask       CommandRules
	MergeMode MergeMode
}

// ResolveConfig loads and merges global config + project override.
// Returns a resolved Config and the effective merge mode used.
//
// Merge-mode resolution (first non-empty wins):
//   1. project.merge_mode    — set in .permission-gate.toml
//   2. global.merge_mode     — set in ~/.config/permission-gate/config.toml
//   3. MergePrepend          — default
//
// Earlier versions of this function read merge_mode from the project config
// only, which meant the global setting was silently ignored. Now the project
// is treated as a partial override: if it doesn't explicitly set merge_mode,
// the value inherits from global (or defaults to prepend).
func ResolveConfig(cwd string) (*Config, MergeMode, error) {
	global, err := loadFile(globalConfigPath())
	if err != nil {
		return nil, "", fmt.Errorf("global config: %w", err)
	}
	project, projectMode := loadProjectConfig(cwd)

	mode := projectMode
	if mode == "" {
		mode = global.MergeMode
	}
	if mode == "" {
		mode = MergePrepend
	}

	gAllow, err := global.Allow.Specs()
	if err != nil {
		return nil, "", fmt.Errorf("global allow: %w", err)
	}
	gDeny, err := global.Deny.Specs()
	if err != nil {
		return nil, "", fmt.Errorf("global deny: %w", err)
	}
	gAsk, err := global.Ask.Specs()
	if err != nil {
		return nil, "", fmt.Errorf("global ask: %w", err)
	}
	pAllow, err := project.Allow.Specs()
	if err != nil {
		return nil, "", fmt.Errorf("project allow: %w", err)
	}
	pDeny, err := project.Deny.Specs()
	if err != nil {
		return nil, "", fmt.Errorf("project deny: %w", err)
	}
	pAsk, err := project.Ask.Specs()
	if err != nil {
		return nil, "", fmt.Errorf("project ask: %w", err)
	}

	resolved := &Config{
		GlobalRaw:  *global,
		ProjectRaw: project,
	}

	switch mode {
	case MergeOverwrite:
		resolved.Allow.Commands = pAllow
		resolved.Deny.Commands = pDeny
		resolved.Ask.Commands = pAsk
	case MergeAppend:
		resolved.Allow.Commands = mergeSpecs(gAllow, pAllow)
		resolved.Deny.Commands = mergeSpecs(gDeny, pDeny)
		resolved.Ask.Commands = mergeSpecs(gAsk, pAsk)
	default: // prepend
		resolved.Allow.Commands = mergeSpecs(pAllow, gAllow)
		resolved.Deny.Commands = mergeSpecs(pDeny, gDeny)
		resolved.Ask.Commands = mergeSpecs(pAsk, gAsk)
	}

	resolved.Allow.Flags = mergeFlags(mode, project.Allow.Flags, global.Allow.Flags)
	resolved.Deny.Flags = mergeFlags(mode, project.Deny.Flags, global.Deny.Flags)
	resolved.Ask.Flags = mergeFlags(mode, project.Ask.Flags, global.Ask.Flags)

	return resolved, mode, nil
}

// mergeSpecs returns primary followed by secondary.
func mergeSpecs(primary, secondary []CommandSpec) []CommandSpec {
	out := make([]CommandSpec, 0, len(primary)+len(secondary))
	out = append(out, primary...)
	out = append(out, secondary...)
	return out
}

// mergeFlags merges project and global flag-rule maps according to the
// merge mode so flag priority matches spec priority:
//   - prepend:  project before global (user-first)
//   - append:   global before project (builtin-first)
//   - overwrite: project only
// The primary map's flags are appended after the secondary map's flags;
// both lists are preserved because the engine evaluates them as a set.
func mergeFlags(mode MergeMode, project, global map[string][]string) map[string][]string {
	if mode == MergeOverwrite {
		result := make(map[string][]string, len(project))
		for k, v := range project {
			result[k] = append([]string{}, v...)
		}
		return result
	}
	var primary, secondary map[string][]string
	if mode == MergeAppend {
		primary, secondary = global, project
	} else {
		primary, secondary = project, global
	}
	result := make(map[string][]string)
	for k, v := range secondary {
		result[k] = append([]string{}, v...)
	}
	for k, v := range primary {
		result[k] = append(result[k], v...)
	}
	return result
}

func globalConfigPath() string {
	if p := os.Getenv("PERMISSION_GATE_CONFIG"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "permission-gate", "config.toml")
}

func projectConfigPath(cwd string) string {
	if p := os.Getenv("PERMISSION_GATE_PROJECT_CONFIG"); p != "" {
		return p
	}
	return filepath.Join(cwd, ".permission-gate.toml")
}

func loadFile(path string) (*RawConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &RawConfig{}, nil
		}
		return nil, err
	}

	var cfg RawConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &cfg, nil
}

// loadProjectConfig reads the project-level config (if any) and returns
// the raw config plus whatever merge_mode it explicitly set. An empty
// MergeMode means "no opinion" — the caller is expected to fall back to
// the global setting (or the default).
func loadProjectConfig(cwd string) (RawConfig, MergeMode) {
	cfg, err := loadFile(projectConfigPath(cwd))
	if err != nil || cfg == nil {
		return RawConfig{}, ""
	}
	return *cfg, cfg.MergeMode
}

// DefaultConfig returns the default global config content for `pgate init`.
func DefaultConfig() string {
	return `# Permission Gate — global configuration
# Path: ~/.config/permission-gate/config.toml
#
# Three tiers: allow (auto-pass), deny (auto-block), ask (prompt user).
#
# Each command entry can be either a plain string (prefix match) or an
# inline table with optional include/exclude refinements:
#
#   commands = [
#     "rg",                                                # bare string: prefix match
#     { cmd = "rm", include_flags = ["-f","-rf","-r"],     # /tmp 下的 rm 才放行
#       include_args = ["/tmp","/private/tmp"] },
#     { cmd = "git clean", exclude_args = ["/", "~"] },    # 禁止 git clean 顶层目录
#   ]
#
# Field semantics (all four are optional):
#   cmd           — required, prefix-matched against the command's leading tokens
#   include_flags — any-of: command must contain at least one of these flags
#   exclude_flags — none-of: command must not contain any of these flags
#   include_args  — all-under: every non-flag arg must live under one of these prefixes
#   exclude_args  — none-prefix: no non-flag arg may live under any of these prefixes
#
# Excludes are checked first; any exclude hit fails the spec. All four fields
# are AND-combined; any field failing makes the whole spec not match.
# Short option bundles (-rf) are expanded on both sides when matching flags.

[allow]
commands = [
    "rg",
]

[deny]
commands = [
    "rm",
]

[ask]
commands = [
]
`
}

// InitConfig creates the default global config file.
func InitConfig() (string, error) {
	path := globalConfigPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}
	if _, err := os.Stat(path); err == nil {
		return path, fmt.Errorf("config already exists at %s", path)
	}
	if err := os.WriteFile(path, []byte(DefaultConfig()), 0644); err != nil {
		return "", fmt.Errorf("write config: %w", err)
	}
	return path, nil
}
