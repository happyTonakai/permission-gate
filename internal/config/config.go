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

// CommandRules are the allow/deny/ask pattern lists for one scope.
type CommandRules struct {
	Commands []string            `toml:"commands,omitempty"`
	Flags    map[string][]string `toml:"flags,omitempty"`
}

func (r CommandRules) IsZero() bool {
	return len(r.Commands) == 0 && len(r.Flags) == 0
}

// RawConfig is the on-disk TOML structure for one config file.
type RawConfig struct {
	Allow CommandRules `toml:"allow"`
	Deny  CommandRules `toml:"deny"`
	Ask   CommandRules `toml:"ask"`

	// MergeMode only used in project-level config
	MergeMode MergeMode `toml:"merge_mode,omitempty"`
}

// Config is the resolved configuration after merging.
type Config struct {
	Allow CommandRules
	Deny  CommandRules
	Ask   CommandRules
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
func ResolveConfig(cwd string) (*Config, MergeMode, error) {
	global, err := loadFile(globalConfigPath())
	if err != nil {
		return nil, "", fmt.Errorf("global config: %w", err)
	}

	project, mode := loadProjectConfig(cwd)

	switch mode {
	case MergeOverwrite:
		return &Config{
			Allow: project.Allow,
			Deny:  project.Deny,
			Ask:   project.Ask,
		}, mode, nil

	case MergeAppend:
		return &Config{
			Allow: mergeRules(global.Allow, project.Allow),
			Deny:  mergeRules(global.Deny, project.Deny),
			Ask:   mergeRules(global.Ask, project.Ask),
		}, mode, nil

	default: // prepend
		return &Config{
			Allow: mergeRules(project.Allow, global.Allow),
			Deny:  mergeRules(project.Deny, global.Deny),
			Ask:   mergeRules(project.Ask, global.Ask),
		}, mode, nil
	}
}

func mergeRules(primary, secondary CommandRules) CommandRules {
	return CommandRules{
		Commands: append(append([]string{}, primary.Commands...), secondary.Commands...),
		Flags:    mergeFlags(primary.Flags, secondary.Flags),
	}
}

func mergeFlags(primary, secondary map[string][]string) map[string][]string {
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

func loadProjectConfig(cwd string) (RawConfig, MergeMode) {
	cfg, err := loadFile(projectConfigPath(cwd))
	if err != nil || cfg == nil {
		return RawConfig{}, MergePrepend
	}
	if cfg.MergeMode == "" {
		cfg.MergeMode = MergePrepend
	}
	return *cfg, cfg.MergeMode
}

// DefaultConfig returns the default global config content for `pgate init`.
func DefaultConfig() string {
	return `# Permission Gate — global configuration
# Path: ~/.config/permission-gate/config.toml
#
# Three tiers: allow (auto-pass), deny (auto-block), ask (prompt user).
# Patterns are prefix-matched against extracted command tokens.
#   "git log" matches "git log --oneline -5"
#   "find"   matches "find . -name '*.go'"

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
