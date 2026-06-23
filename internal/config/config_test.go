package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempConfig(t *testing.T, dir, filename, content string) {
	t.Helper()
	path := filepath.Join(dir, filename)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == "" {
		t.Fatal("default config should not be empty")
	}
}

func TestLoadFile(t *testing.T) {
	content := `
[allow]
commands = ["ls", "cat"]

[deny]
commands = ["rm"]

[ask]
commands = ["git push"]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := loadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Allow.Commands) != 2 {
		t.Errorf("expected 2 allow commands, got %d", len(cfg.Allow.Commands))
	}
	if len(cfg.Deny.Commands) != 1 {
		t.Errorf("expected 1 deny command, got %d", len(cfg.Deny.Commands))
	}
	if len(cfg.Ask.Commands) != 1 {
		t.Errorf("expected 1 ask command, got %d", len(cfg.Ask.Commands))
	}
}

func TestLoadFileWithFlags(t *testing.T) {
	content := `
[deny.flags]
find = ["-exec", "-delete"]
sed = ["-i"]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := loadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Deny.Flags) != 2 {
		t.Errorf("expected 2 flag rules, got %d", len(cfg.Deny.Flags))
	}
	if len(cfg.Deny.Flags["find"]) != 2 {
		t.Errorf("expected 2 find flags, got %d", len(cfg.Deny.Flags["find"]))
	}
}

func TestLoadNonexistentFile(t *testing.T) {
	cfg, err := loadFile("/nonexistent/path.toml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("expected empty config, got nil")
	}
}

func TestMergePrepend(t *testing.T) {
	global := RawConfig{
		Allow: CommandRules{Commands: []string{"ls", "cat"}},
		Deny:  CommandRules{Commands: []string{"rm"}},
	}
	project := RawConfig{
		Allow:     CommandRules{Commands: []string{"git"}},
		MergeMode: MergePrepend,
	}

	merged := mergeRules(project.Allow, global.Allow)
	if len(merged.Commands) != 3 {
		t.Errorf("expected 3 commands (project first), got %d: %v", len(merged.Commands), merged.Commands)
	}
	if merged.Commands[0] != "git" {
		t.Errorf("expected project rule 'git' first, got %s", merged.Commands[0])
	}
}

func TestMergeAppend(t *testing.T) {
	global := RawConfig{
		Allow: CommandRules{Commands: []string{"ls", "cat"}},
	}
	project := RawConfig{
		Allow:     CommandRules{Commands: []string{"git"}},
		MergeMode: MergeAppend,
	}

	merged := mergeRules(project.Allow, global.Allow)
	if len(merged.Commands) != 3 {
		t.Errorf("expected 3 commands, got %d", len(merged.Commands))
	}
	if merged.Commands[0] != "git" {
		t.Errorf("expected project rule 'git' at start (prepend by default), got %s", merged.Commands[0])
	}
}

func TestInitConfig(t *testing.T) {
	// Override the config path to use a temp dir
	old := os.Getenv("PERMISSION_GATE_CONFIG")
	defer os.Setenv("PERMISSION_GATE_CONFIG", old)
	os.Setenv("PERMISSION_GATE_CONFIG", filepath.Join(t.TempDir(), "config.toml"))

	path, err := InitConfig()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("config file should exist at %s", path)
	}

	// Second call should error (already exists)
	_, err = InitConfig()
	if err == nil {
		t.Error("expected error on second init")
	}
}

func TestConfigProjectPath(t *testing.T) {
	path := projectConfigPath("/some/project")
	if path != "/some/project/.permission-gate.toml" {
		t.Errorf("unexpected project config path: %s", path)
	}
}

func TestConfigGlobalPathWithEnv(t *testing.T) {
	old := os.Getenv("PERMISSION_GATE_CONFIG")
	defer os.Setenv("PERMISSION_GATE_CONFIG", old)
	os.Setenv("PERMISSION_GATE_CONFIG", "/custom/path/config.toml")

	path := globalConfigPath()
	if path != "/custom/path/config.toml" {
		t.Errorf("expected custom path, got %s", path)
	}
}

func TestProjectOverrideEnv(t *testing.T) {
	old := os.Getenv("PERMISSION_GATE_PROJECT_CONFIG")
	defer os.Setenv("PERMISSION_GATE_PROJECT_CONFIG", old)
	os.Setenv("PERMISSION_GATE_PROJECT_CONFIG", "/custom/.permission-gate.toml")

	path := projectConfigPath("/some/project")
	if path != "/custom/.permission-gate.toml" {
		t.Errorf("expected custom project path, got %s", path)
	}
}

func TestMergeFlags(t *testing.T) {
	primary := map[string][]string{
		"find": {"-exec"},
	}
	secondary := map[string][]string{
		"find": {"-delete"},
		"sed":  {"-i"},
	}

	result := mergeFlags(primary, secondary)
	if len(result) != 2 {
		t.Errorf("expected 2 commands, got %d", len(result))
	}
	// primary takes priority (prepend mode)
	if len(result["find"]) != 2 {
		t.Errorf("expected find to have 2 flags, got %d: %v", len(result["find"]), result["find"])
	}
}
