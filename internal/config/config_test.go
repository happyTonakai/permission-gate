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

	// Resolve and verify all entries are bare strings (no refinements).
	allowSpecs, err := cfg.Allow.Specs()
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range allowSpecs {
		if s.Cmd == "" {
			t.Errorf("allow[%d]: empty cmd", i)
		}
		if len(s.IncludeFlags) != 0 || len(s.ExcludeFlags) != 0 ||
			len(s.IncludeArgs) != 0 || len(s.ExcludeArgs) != 0 {
			t.Errorf("bare string spec should have no refinements, got %+v", s)
		}
	}
}

func TestLoadFileWithInlineTable(t *testing.T) {
	content := `
[allow]
commands = [
  { cmd = "rm", include_flags = ["-f", "-rf", "-r"], include_args = ["/tmp"] },
  { cmd = "git clean", exclude_args = ["/", "~"] },
]

[deny]
commands = [
  { cmd = "rm", exclude_args = ["/tmp", "/private/tmp"] },
]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := loadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	allowSpecs, err := cfg.Allow.Specs()
	if err != nil {
		t.Fatalf("allow specs: %v", err)
	}
	if len(allowSpecs) != 2 {
		t.Fatalf("expected 2 allow specs, got %d", len(allowSpecs))
	}

	rm := allowSpecs[0]
	if rm.Cmd != "rm" {
		t.Errorf("rm cmd = %q, want rm", rm.Cmd)
	}
	if len(rm.IncludeFlags) != 3 {
		t.Errorf("expected 3 include_flags, got %v", rm.IncludeFlags)
	}
	if len(rm.IncludeArgs) != 1 || rm.IncludeArgs[0] != "/tmp" {
		t.Errorf("include_args = %v, want [/tmp]", rm.IncludeArgs)
	}

	clean := allowSpecs[1]
	if clean.Cmd != "git clean" {
		t.Errorf("git clean cmd = %q", clean.Cmd)
	}
	if len(clean.ExcludeArgs) != 2 {
		t.Errorf("expected 2 exclude_args, got %v", clean.ExcludeArgs)
	}

	denySpecs, err := cfg.Deny.Specs()
	if err != nil {
		t.Fatal(err)
	}
	if len(denySpecs) != 1 {
		t.Fatalf("expected 1 deny spec, got %d", len(denySpecs))
	}
	if denySpecs[0].Cmd != "rm" || len(denySpecs[0].ExcludeArgs) != 2 {
		t.Errorf("deny spec wrong: %+v", denySpecs[0])
	}
}

func TestLoadFileRejectsBadInlineTable(t *testing.T) {
	// Missing `cmd` field should be rejected.
	content := `
[allow]
commands = [{ include_flags = ["-f"] }]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := loadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Allow.Specs(); err == nil {
		t.Fatal("expected error parsing spec without cmd field")
	}
}

func TestLoadFileRejectsBadEntryType(t *testing.T) {
	// Integer entries are neither string nor inline-table.
	content := `
[allow]
commands = [42]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := loadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Allow.Specs(); err == nil {
		t.Fatal("expected error for integer command entry")
	}
}

func TestLoadFileMixedStringAndTable(t *testing.T) {
	content := `
[allow]
commands = ["rg", { cmd = "rm", include_args = ["/tmp"] }]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := loadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := cfg.Allow.Specs()
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 {
		t.Fatalf("expected 2 specs, got %d", len(specs))
	}
	if specs[0].Cmd != "rg" {
		t.Errorf("specs[0].Cmd = %q, want rg", specs[0].Cmd)
	}
	if specs[1].Cmd != "rm" || len(specs[1].IncludeArgs) != 1 {
		t.Errorf("specs[1] = %+v, want rm with one include_arg", specs[1])
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
		Allow: RawRules{Commands: []any{"ls", "cat"}},
		Deny:  RawRules{Commands: []any{"rm"}},
	}
	project := RawConfig{
		Allow:     RawRules{Commands: []any{"git"}},
		MergeMode: MergePrepend,
	}

	merged, err := mergeRawForTest(project.Allow, global.Allow)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 3 {
		t.Fatalf("expected 3 commands (project first), got %d", len(merged))
	}
	if merged[0].Cmd != "git" {
		t.Errorf("expected project rule 'git' first, got %s", merged[0].Cmd)
	}
}

func TestMergeAppend(t *testing.T) {
	global := RawConfig{
		Allow: RawRules{Commands: []any{"ls", "cat"}},
	}
	project := RawConfig{
		Allow:     RawRules{Commands: []any{"git"}},
		MergeMode: MergeAppend,
	}

	// In MergeAppend mode (built-in checked first), global comes first,
	// project is appended after — mirroring ResolveConfig's MergeAppend branch.
	merged, err := mergeRawForTest(global.Allow, project.Allow)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 3 {
		t.Fatalf("expected 3 commands, got %d", len(merged))
	}
	if merged[0].Cmd != "ls" {
		t.Errorf("expected global 'ls' first (append mode), got %s", merged[0].Cmd)
	}
}

// mergeRawForTest is a test-only helper: parse raw rules, then merge specs
// using the same mergeSpecs logic as ResolveConfig.
func mergeRawForTest(primary, secondary RawRules) ([]CommandSpec, error) {
	p, err := primary.Specs()
	if err != nil {
		return nil, err
	}
	s, err := secondary.Specs()
	if err != nil {
		return nil, err
	}
	return mergeSpecs(p, s), nil
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
	project := map[string][]string{
		"find": {"-exec"},
	}
	global := map[string][]string{
		"find": {"-delete"},
		"sed":  {"-i"},
	}

	// prepend: project first, global appended.
	result := mergeFlags(MergePrepend, project, global)
	if len(result) != 2 {
		t.Errorf("expected 2 commands, got %d", len(result))
	}
	if len(result["find"]) != 2 {
		t.Errorf("expected find to have 2 flags, got %d: %v", len(result["find"]), result["find"])
	}

	// append: global first, project appended.
	result = mergeFlags(MergeAppend, project, global)
	if len(result["find"]) != 2 {
		t.Errorf("expected find to have 2 flags (append), got %d: %v", len(result["find"]), result["find"])
	}

	// overwrite: project only.
	result = mergeFlags(MergeOverwrite, project, global)
	if _, ok := result["sed"]; ok {
		t.Errorf("overwrite should drop global 'sed', got %v", result)
	}
	if len(result["find"]) != 1 || result["find"][0] != "-exec" {
		t.Errorf("overwrite should keep only project 'find' flags, got %v", result["find"])
	}
}
