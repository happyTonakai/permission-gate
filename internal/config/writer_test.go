package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// withConfigEnv points PERMISSION_GATE_CONFIG at path so globalConfigPath()
// resolves there, and clears PERMISSION_GATE_PROJECT_CONFIG so the project
// resolution always reads from cwd. Cleanup is restored at test end.
func withConfigEnv(t *testing.T, globalPath string) {
	t.Helper()
	t.Setenv("PERMISSION_GATE_CONFIG", globalPath)
	t.Setenv("PERMISSION_GATE_PROJECT_CONFIG", "")
}

// spliceForTest is a thin wrapper exposing the unexported splice for tests
// without duplicating the call chain. Returns (newBytes, dedup, err).
func spliceForTest(content []byte, spec string) ([]byte, bool, error) {
	return spliceAllowCommand(content, spec)
}

// ─── File-level behavior (AddAllowCommand) ────────────────────

func TestAddAllowCommand_CreatesMissingFile(t *testing.T) {
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "config.toml")
	withConfigEnv(t, globalPath)

	path, added, err := AddAllowCommand("rg", ScopeUser)
	if err != nil {
		t.Fatal(err)
	}
	if path != globalPath {
		t.Errorf("path = %q, want %q", path, globalPath)
	}
	if !added {
		t.Error("expected added=true for first add")
	}

	data, err := os.ReadFile(globalPath)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	var cfg RawConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse written file: %v", err)
	}
	if len(cfg.Allow.Commands) != 1 {
		t.Fatalf("expected 1 allow cmd, got %d", len(cfg.Allow.Commands))
	}
	if s, _ := cfg.Allow.Commands[0].(string); s != "rg" {
		t.Errorf("allow[0] = %v, want %q", cfg.Allow.Commands[0], "rg")
	}
}

func TestAddAllowCommand_AppendsToSingleLine(t *testing.T) {
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "config.toml")
	withConfigEnv(t, globalPath)

	if err := os.WriteFile(globalPath, []byte(`[allow]
commands = ["ls", "cat"]
`), 0644); err != nil {
		t.Fatal(err)
	}

	path, added, err := AddAllowCommand("rg", ScopeUser)
	if err != nil {
		t.Fatal(err)
	}
	if path != globalPath {
		t.Errorf("path = %q, want %q", path, globalPath)
	}
	if !added {
		t.Error("expected added=true for new entry")
	}

	data, _ := os.ReadFile(globalPath)
	got := strings.TrimSpace(string(data))
	want := `[allow]
commands = ["ls", "cat", "rg"]`
	if got != want {
		t.Errorf("output mismatch:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestAddAllowCommand_AppendsToMultiLineWithTrailingComma(t *testing.T) {
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "config.toml")
	withConfigEnv(t, globalPath)

	input := "[allow]\ncommands = [\n    \"rg\",\n    \"fd\",\n    \"bat\",\n]\n"
	if err := os.WriteFile(globalPath, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	if _, added, err := AddAllowCommand("delta", ScopeUser); err != nil || !added {
		t.Fatalf("err=%v added=%v", err, added)
	}

	data, _ := os.ReadFile(globalPath)
	got := string(data)
	want := "[allow]\ncommands = [\n    \"rg\",\n    \"fd\",\n    \"bat\",\n    \"delta\"\n]\n"
	if got != want {
		t.Errorf("output mismatch:\ngot:  %s\nwant: %s", got, want)
	}
}

func TestAddAllowCommand_AppendsToMultiLineWithoutTrailingComma(t *testing.T) {
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "config.toml")
	withConfigEnv(t, globalPath)

	input := "[allow]\ncommands = [\n    \"rg\",\n    \"fd\",\n    \"bat\"\n]\n"
	if err := os.WriteFile(globalPath, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	if _, _, err := AddAllowCommand("delta", ScopeUser); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(globalPath)
	got := string(data)
	want := "[allow]\ncommands = [\n    \"rg\",\n    \"fd\",\n    \"bat\",\n    \"delta\"\n]\n"
	if got != want {
		t.Errorf("output mismatch:\ngot:  %s\nwant: %s", got, want)
	}
}

func TestAddAllowCommand_EmptyArrayBecomesSingle(t *testing.T) {
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "config.toml")
	withConfigEnv(t, globalPath)

	if err := os.WriteFile(globalPath, []byte("[allow]\ncommands = []\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AddAllowCommand("delta", ScopeUser); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(globalPath)
	if got := strings.TrimSpace(string(data)); got != "[allow]\ncommands = [\"delta\"]" {
		t.Errorf("got %q", got)
	}
}

func TestAddAllowCommand_IdempotentExactString(t *testing.T) {
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "config.toml")
	withConfigEnv(t, globalPath)

	input := "[allow]\ncommands = [\n    \"rg\",\n    \"fd\",\n]\n"
	if err := os.WriteFile(globalPath, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	// Capture original bytes; dedup must NOT touch the file.
	origBytes, _ := os.ReadFile(globalPath)

	_, added, err := AddAllowCommand("rg", ScopeUser)
	if err != nil {
		t.Fatal(err)
	}
	if added {
		t.Error("dedup hit should report added=false")
	}

	afterBytes, _ := os.ReadFile(globalPath)
	if string(origBytes) != string(afterBytes) {
		t.Error("dedup hit must leave file bytes unchanged")
	}
}

func TestAddAllowCommand_PreservesComments(t *testing.T) {
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "config.toml")
	withConfigEnv(t, globalPath)

	input := `# Permission Gate — global configuration
# Path: ~/.config/permission-gate/config.toml
#
# Three tiers: allow (auto-pass), deny (auto-block), ask (prompt user).

[allow]
commands = [
    "rg",
    "fd",
]
`
	if err := os.WriteFile(globalPath, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	if _, _, err := AddAllowCommand("delta", ScopeUser); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(globalPath)
	got := string(data)

	// Header comments must still be there.
	for _, line := range []string{
		"# Permission Gate — global configuration",
		"# Path: ~/.config/permission-gate/config.toml",
		"# Three tiers: allow (auto-pass), deny (auto-block), ask (prompt user).",
	} {
		if !strings.Contains(got, line) {
			t.Errorf("comment lost: %q\nfile:\n%s", line, got)
		}
	}

	// "delta" was inserted.
	if !strings.Contains(got, "\"delta\"") {
		t.Errorf("delta not inserted:\n%s", got)
	}

	// And the rest of the content is unchanged byte-for-byte above the
	// insertion point. We check this by ensuring the leading bytes
	// (everything before "delta" appears) are exactly the original
	// header + [allow] + the entries that came before.
	prefix := got[:strings.Index(got, "\"delta\"")]
	wantPrefix := "# Permission Gate — global configuration\n# Path: ~/.config/permission-gate/config.toml\n#\n# Three tiers: allow (auto-pass), deny (auto-block), ask (prompt user).\n\n[allow]\ncommands = [\n    \"rg\",\n    \"fd\",\n    "
	if prefix != wantPrefix {
		t.Errorf("prefix changed:\ngot:\n%s\nwant:\n%s", prefix, wantPrefix)
	}
}

// TestAddAllowCommand_PreservesMergeModeAtBottom is the regression test
// for the go-toml/v2 quirk that motivated text-level editing. Earlier
// versions used marshal/unmarshal round-trip and silently dropped
// `merge_mode = "..."` placed AFTER a [table] header. The new code
// never re-parses, so the line survives intact.
func TestAddAllowCommand_PreservesMergeModeAtBottom(t *testing.T) {
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "config.toml")
	withConfigEnv(t, globalPath)

	input := `[allow]
commands = ["rg"]

[deny]
commands = ["rm"]

[ask]
commands = ["git push"]

# merge_mode placed AFTER [ask] (the quirk case)
merge_mode = "append"
`
	if err := os.WriteFile(globalPath, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	if _, _, err := AddAllowCommand("delta", ScopeUser); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(globalPath)
	if !strings.Contains(string(data), `merge_mode = "append"`) {
		t.Errorf("merge_mode at bottom was lost:\n%s", data)
	}
	// And it's still on the same line (not moved or reformatted).
	if !strings.Contains(string(data), "\nmerge_mode = \"append\"\n") {
		t.Errorf("merge_mode at bottom lost its position:\n%s", data)
	}
}

func TestAddAllowCommand_PreservesInlineTables(t *testing.T) {
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "config.toml")
	withConfigEnv(t, globalPath)

	input := `[allow]
commands = [
    "rg",
    { cmd = "rm", include_args = ["/tmp", "/private/tmp"] },
    "fd",
]
`
	if err := os.WriteFile(globalPath, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	if _, _, err := AddAllowCommand("delta", ScopeUser); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(globalPath)
	if !strings.Contains(string(data), `{ cmd = "rm", include_args = ["/tmp", "/private/tmp"] },`) {
		t.Errorf("inline table not preserved:\n%s", data)
	}
	if !strings.Contains(string(data), `"delta"`) {
		t.Errorf("delta not inserted:\n%s", data)
	}
}

func TestAddAllowCommand_PreservesCommentsInsideArray(t *testing.T) {
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "config.toml")
	withConfigEnv(t, globalPath)

	input := `[allow]
commands = [
    "rg",
    # this is a comment
    "fd",
]
`
	if err := os.WriteFile(globalPath, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	if _, _, err := AddAllowCommand("delta", ScopeUser); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(globalPath)
	if !strings.Contains(string(data), "# this is a comment") {
		t.Errorf("comment inside array lost:\n%s", data)
	}
}

func TestAddAllowCommand_EscapesSpecialChars(t *testing.T) {
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "config.toml")
	withConfigEnv(t, globalPath)

	if err := os.WriteFile(globalPath, []byte("[allow]\ncommands = [\"rg\"]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// A spec containing characters that need TOML basic-string escaping.
	if _, _, err := AddAllowCommand(`weird"name\back`, ScopeUser); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(globalPath)
	// Must contain the properly escaped form so go-toml can re-parse.
	if !strings.Contains(string(data), `"weird\"name\\back"`) {
		t.Errorf("spec not properly escaped:\n%s", data)
	}

	// Verify go-toml round-trips back to the original spec.
	var cfg RawConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("reparse failed: %v\n%s", err, data)
	}
	last := cfg.Allow.Commands[len(cfg.Allow.Commands)-1]
	if s, _ := last.(string); s != `weird"name\back` {
		t.Errorf("reparsed spec = %q, want %q", s, `weird"name\back`)
	}
}

// ─── [allow] section missing / partial ────────────────────────

func TestAddAllowCommand_NoAllowSection_AppendsNewOne(t *testing.T) {
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "config.toml")
	withConfigEnv(t, globalPath)

	input := "# Only deny, no allow\n[deny]\ncommands = [\"rm\"]\n"
	if err := os.WriteFile(globalPath, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	if _, _, err := AddAllowCommand("delta", ScopeUser); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(globalPath)
	got := string(data)
	if !strings.Contains(got, "[deny]") || !strings.Contains(got, "[allow]") {
		t.Errorf("section structure broken:\n%s", got)
	}
	if !strings.Contains(got, "\"delta\"") {
		t.Errorf("delta not inserted:\n%s", got)
	}
	// Comment above must survive.
	if !strings.HasPrefix(got, "# Only deny, no allow\n") {
		t.Errorf("leading comment lost:\n%s", got)
	}
}

func TestAddAllowCommand_AllowSectionNoCommandsLine_InsertsOne(t *testing.T) {
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "config.toml")
	withConfigEnv(t, globalPath)

	input := "[allow]\n\n[deny]\ncommands = [\"rm\"]\n"
	if err := os.WriteFile(globalPath, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	if _, _, err := AddAllowCommand("delta", ScopeUser); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(globalPath)
	got := string(data)
	if !strings.Contains(got, "[allow]\ncommands = [\"delta\"]") {
		t.Errorf("commands line not inserted correctly:\n%s", got)
	}
	if !strings.Contains(got, "[deny]") {
		t.Errorf("[deny] section lost:\n%s", got)
	}
}

// ─── Scope resolution ─────────────────────────────────────────

func TestAddAllowCommand_ProjectScopeWritesCwdFile(t *testing.T) {
	cwd := t.TempDir()
	withConfigEnv(t, filepath.Join(t.TempDir(), "global.toml"))
	t.Chdir(cwd)

	path, added, err := AddAllowCommand("npm", ScopeProject)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(cwd, ".permission-gate.toml")
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if !added {
		t.Error("expected added=true")
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("project file not created: %v", err)
	}
}

func TestAddAllowCommand_ProjectScopeHonorsEnvOverride(t *testing.T) {
	cwd := t.TempDir()
	custom := filepath.Join(t.TempDir(), "custom.toml")
	t.Chdir(cwd)
	t.Setenv("PERMISSION_GATE_CONFIG", filepath.Join(t.TempDir(), "global.toml"))
	t.Setenv("PERMISSION_GATE_PROJECT_CONFIG", custom)

	path, _, err := AddAllowCommand("npm", ScopeProject)
	if err != nil {
		t.Fatal(err)
	}
	if path != custom {
		t.Errorf("project env override not honored: got %q, want %q", path, custom)
	}
}

func TestAddAllowCommand_CreatesParentDir(t *testing.T) {
	parent := t.TempDir()
	cwd := filepath.Join(parent, "deeply", "nested")
	if err := os.MkdirAll(cwd, 0755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)

	deep := filepath.Join(cwd, ".config", "permission-gate", "config.toml")
	t.Setenv("PERMISSION_GATE_CONFIG", deep)

	path, _, err := AddAllowCommand("pnpm", ScopeUser)
	if err != nil {
		t.Fatalf("expected MkdirAll to create dir: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Errorf("parent dir missing: %v", err)
	}
}

// ─── ParseScope ───────────────────────────────────────────────

func TestParseScope(t *testing.T) {
	cases := []struct {
		in      string
		want    Scope
		wantErr bool
	}{
		{"", ScopeUser, false}, // default
		{"user", ScopeUser, false},
		{"project", ScopeProject, false},
		{"USER", "", true}, // case-sensitive on purpose: matches Scope casing exactly
		{"global", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseScope(tc.in)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// ─── Direct spliceAllowCommand tests (no disk I/O) ────────────

// TestSpliceEmptyArray inserts into a `commands = []` form.
func TestSpliceEmptyArray(t *testing.T) {
	in := []byte("[allow]\ncommands = []\n")
	out, dedup, err := spliceForTest(in, "delta")
	if err != nil {
		t.Fatal(err)
	}
	if dedup {
		t.Fatal("empty array should not be a dedup hit")
	}
	if string(out) != "[allow]\ncommands = [\"delta\"]\n" {
		t.Errorf("got %q", out)
	}
}

// TestSpliceDedupMatchesBareStringInsideArray is the regression for the
// bare-string dedup path. Earlier implementations incorrectly treated an
// inline-table-form spec as a duplicate of the bare-string form.
func TestSpliceDedupMatchesBareStringInsideArray(t *testing.T) {
	in := []byte("[allow]\ncommands = [\"rg\"]\n")
	out, dedup, err := spliceForTest(in, "rg")
	if err != nil {
		t.Fatal(err)
	}
	if !dedup {
		t.Error("expected dedup=true")
	}
	if string(out) != string(in) {
		t.Error("dedup must return content unchanged")
	}
}

// TestSpliceDoesNotMatchInlineTableAsDuplicate: an inline-table spec
// `{ cmd = "rg" }` should NOT count as a duplicate of the bare-string
// spec "rg". We accept that this means a second `pgate add rg` will
// write a redundant bare-string entry — both rules match the same
// tokens, so the redundancy is harmless and the cost of false-positive
// dedup (silently dropping a user's explicit ask) is worse.
func TestSpliceDoesNotMatchInlineTableAsDuplicate(t *testing.T) {
	in := []byte("[allow]\ncommands = [{ cmd = \"rg\" }]\n")
	out, dedup, err := spliceForTest(in, "rg")
	if err != nil {
		t.Fatal(err)
	}
	if dedup {
		t.Error("inline-table form should not count as duplicate of bare string")
	}
	if !strings.Contains(string(out), "\"rg\"") {
		t.Errorf("expected bare-string entry to be appended:\n%s", out)
	}
}

// TestSpliceHandlesBracketsInInlineTableFlags verifies the arrayScanner
// doesn't get confused by `]` characters inside inline tables. The
// `include_args = ["/tmp"]` would be mis-counted by a naïve bracket
// counter.
func TestSpliceHandlesBracketsInInlineTableFlags(t *testing.T) {
	in := []byte(`[allow]
commands = [
    { cmd = "rm", include_args = ["/tmp", "/private/tmp"] },
]
`)
	out, dedup, err := spliceForTest(in, "rg")
	if err != nil {
		t.Fatalf("splice failed: %v", err)
	}
	if dedup {
		t.Error("expected dedup=false")
	}
	got := string(out)
	if !strings.Contains(got, `{ cmd = "rm", include_args = ["/tmp", "/private/tmp"] },`) {
		t.Errorf("inline table got mangled:\n%s", got)
	}
	if !strings.Contains(got, "    \"rg\"\n]") {
		t.Errorf("new entry not placed correctly:\n%s", got)
	}
}

// TestSpliceHandlesCommentsInsideArray: arrayScanner must skip `#` to EOL.
func TestSpliceHandlesCommentsInsideArray(t *testing.T) {
	in := []byte(`[allow]
commands = [
    "rg",
    # inline comment
    "fd",
]
`)
	out, _, err := spliceForTest(in, "delta")
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, "# inline comment") {
		t.Errorf("comment lost:\n%s", got)
	}
}

// TestSpliceDistinguishesAllowFromLongerSectionNames verifies that
// `[allow]` matches exactly and not `[allowing]` etc.
func TestSpliceDistinguishesAllowFromLongerSectionNames(t *testing.T) {
	// File has only [allowing] — no [allow] section. We should append a
	// new [allow] section, NOT inject into the unrelated [allowing].
	in := []byte(`[allowing]
commands = ["x"]
`)
	out, _, err := spliceForTest(in, "delta")
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, "[allowing]") || !strings.Contains(got, "[allow]") {
		t.Errorf("section distinction broken:\n%s", got)
	}
	if !strings.Contains(got, "[allow]\ncommands = [\"delta\"]") {
		t.Errorf("new [allow] section missing or malformed:\n%s", got)
	}
}

// TestSpliceHandlesMultiLineValueContinuation covers the H2 regression
// flagged by the go-reviewer: a TOML file with the array literal on the
// line AFTER `commands =` (legal TOML — `=` may be followed by a newline
// before the value). Without continuation handling, findCommandsLine
// would conclude "no commands line" and spliceAllowCommand would inject
// a duplicate `commands =` line, producing invalid TOML.
func TestSpliceHandlesMultiLineValueContinuation(t *testing.T) {
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "config.toml")
	withConfigEnv(t, globalPath)

	in := `[allow]
commands =
["rg", "fd"]
`
	if err := os.WriteFile(globalPath, []byte(in), 0644); err != nil {
		t.Fatal(err)
	}

	if _, added, err := AddAllowCommand("delta", ScopeUser); err != nil || !added {
		t.Fatalf("err=%v added=%v", err, added)
	}

	data, _ := os.ReadFile(globalPath)
	got := string(data)

	// Must NOT contain a second "commands =" line (the original is the one
	// being extended; injecting a new one would produce duplicate-key TOML).
	if c := strings.Count(got, "commands ="); c != 1 {
		t.Errorf("expected exactly 1 'commands =' line, got %d:\n%s", c, got)
	}

	// "delta" should appear inside the array.
	if !strings.Contains(got, "\"delta\"") {
		t.Errorf("delta not inserted:\n%s", got)
	}

	// And the original entries are still there.
	for _, want := range []string{"\"rg\"", "\"fd\""} {
		if !strings.Contains(got, want) {
			t.Errorf("%s lost from array:\n%s", want, got)
		}
	}
}
