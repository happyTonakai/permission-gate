package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestLoadFileParsesMsgField(t *testing.T) {
	// `msg` is a user-authored hint that travels through to the deny
	// verdict. It must round-trip through RawRules → Specs() unchanged.
	content := `
[deny]
commands = [
  "rm",
  { cmd = "git push", include_flags = ["--force"],
    msg = "Force-push rewrites shared history." },
]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := loadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := cfg.Deny.Specs()
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 {
		t.Fatalf("expected 2 deny specs, got %d", len(specs))
	}

	// Bare string: msg stays empty.
	if specs[0].Msg != "" {
		t.Errorf("bare-string spec should have empty Msg, got %q", specs[0].Msg)
	}

	// Inline table: msg is preserved verbatim, including punctuation and
	// trailing period (we don't trim — what the user wrote is what they
	// see).
	push := specs[1]
	if push.Cmd != "git push" {
		t.Errorf("git push cmd = %q", push.Cmd)
	}
	if len(push.IncludeFlags) != 1 || push.IncludeFlags[0] != "--force" {
		t.Errorf("include_flags = %v", push.IncludeFlags)
	}
	want := "Force-push rewrites shared history."
	if push.Msg != want {
		t.Errorf("Msg = %q, want %q", push.Msg, want)
	}
}

func TestLoadFileRejectsNonStringMsg(t *testing.T) {
	// A `msg` field typed as something other than a string is a
	// configuration error — silently dropping it would hide the
	// misconfiguration from the user, so we surface it.
	content := `
[deny]
commands = [{ cmd = "rm", msg = 42 }]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := loadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Deny.Specs(); err == nil {
		t.Fatal("expected error for non-string msg field")
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

// TestResolveConfigMergeModeFallback verifies the merge_mode resolution
// chain. Earlier code read merge_mode from the project config only and
// silently ignored the global setting. The fix lets the global value
// take effect when the project config doesn't set one (or doesn't exist).
//
// Resolution order (first non-empty wins):
//  1. project.merge_mode    (set in .permission-gate.toml)
//  2. global.merge_mode     (set in ~/.config/permission-gate/config.toml)
//  3. MergePrepend          (default)
func TestResolveConfigMergeModeFallback(t *testing.T) {
	// Use temp HOME for global config and a temp dir as cwd for project.
	tmp := t.TempDir()
	cwd := filepath.Join(tmp, "project")
	if err := os.MkdirAll(cwd, 0755); err != nil {
		t.Fatal(err)
	}
	globalPath := filepath.Join(tmp, "config.toml")
	projectPath := filepath.Join(cwd, ".permission-gate.toml")

	withEnv := func(k, v string) func() {
		old := os.Getenv(k)
		os.Setenv(k, v)
		return func() { os.Setenv(k, old) }
	}
	withGlobal := func(content string) func() {
		os.WriteFile(globalPath, []byte(content), 0644)
		return withEnv("PERMISSION_GATE_CONFIG", globalPath)
	}
	withProject := func(content string) {
		if content == "" {
			os.Remove(projectPath)
		} else {
			os.WriteFile(projectPath, []byte(content), 0644)
		}
	}
	restore := withEnv("PERMISSION_GATE_PROJECT_CONFIG", "") // force load via cwd
	defer restore()

	cases := []struct {
		name    string
		global  string
		project string
		want    MergeMode
	}{
		{"neither set → prepend", "", "", MergePrepend},
		{"only global set → global wins", `merge_mode = "overwrite"`, "", MergeOverwrite},
		{"only project set → project wins", "", `merge_mode = "append"`, MergeAppend},
		{"both set, project wins", `merge_mode = "overwrite"`, `merge_mode = "append"`, MergeAppend},
		{"global set, project exists but no merge_mode → global inherits", `merge_mode = "overwrite"`, "[deny]\ncommands = [\"x\"]", MergeOverwrite},
		{"global no merge_mode, project set → project wins", "[deny]\ncommands = [\"x\"]", `merge_mode = "append"`, MergeAppend},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restoreGlobal := withGlobal(tc.global)
			defer restoreGlobal()
			withProject(tc.project)

			_, mode, err := ResolveConfig(cwd)
			if err != nil {
				t.Fatal(err)
			}
			if mode != tc.want {
				t.Errorf("mode = %q, want %q", mode, tc.want)
			}
		})
	}
}

// TestResolveConfigErrorPaths covers the failure modes ResolveConfig can
// surface. Errors should be specific enough that the user can tell which
// config (global vs project) and which field is wrong, instead of getting
// a generic "config invalid" message.
func TestResolveConfigErrorPaths(t *testing.T) {
	tmp := t.TempDir()
	cwd := filepath.Join(tmp, "project")
	if err := os.MkdirAll(cwd, 0755); err != nil {
		t.Fatal(err)
	}
	globalPath := filepath.Join(tmp, "config.toml")
	projectPath := filepath.Join(cwd, ".permission-gate.toml")

	withGlobal := func(content string) {
		os.WriteFile(globalPath, []byte(content), 0644)
		os.Setenv("PERMISSION_GATE_CONFIG", globalPath)
		os.Setenv("PERMISSION_GATE_PROJECT_CONFIG", "")
	}
	withProject := func(content string) {
		if content == "" {
			os.Remove(projectPath)
		} else {
			os.WriteFile(projectPath, []byte(content), 0644)
		}
	}
	withGlobal("")
	defer func() {
		os.Unsetenv("PERMISSION_GATE_CONFIG")
		os.Unsetenv("PERMISSION_GATE_PROJECT_CONFIG")
	}()

	t.Run("global TOML syntax error", func(t *testing.T) {
		withGlobal(`[deny` + "\nunterminated") // missing closing bracket
		withProject("")
		_, _, err := ResolveConfig(cwd)
		if err == nil {
			t.Fatal("expected error for malformed global TOML")
		}
		if !strings.Contains(err.Error(), "global config") {
			t.Errorf("error should mention global config: %v", err)
		}
	})

	t.Run("global inline table missing cmd field", func(t *testing.T) {
		withGlobal("[deny]\ncommands = [{ exclude_flags = [\"-x\"] }]")
		withProject("")
		_, _, err := ResolveConfig(cwd)
		if err == nil {
			t.Fatal("expected error for inline table without cmd")
		}
		if !strings.Contains(err.Error(), "global") {
			t.Errorf("error should mention global: %v", err)
		}
	})

	t.Run("project inline table wrong type", func(t *testing.T) {
		withGlobal("")
		withProject("[allow]\ncommands = [{ cmd = 42 }]") // cmd should be string
		_, _, err := ResolveConfig(cwd)
		if err == nil {
			t.Fatal("expected error for wrong cmd type")
		}
		if !strings.Contains(err.Error(), "project") {
			t.Errorf("error should mention project: %v", err)
		}
	})

	t.Run("neither file present still succeeds", func(t *testing.T) {
		withGlobal("")
		withProject("")
		_, mode, err := ResolveConfig(cwd)
		if err != nil {
			t.Fatalf("absent files should not error: %v", err)
		}
		if mode != MergePrepend {
			t.Errorf("mode = %q, want %q (default)", mode, MergePrepend)
		}
	})
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
