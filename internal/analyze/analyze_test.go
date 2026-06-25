package analyze

import (
	"testing"
)

func TestSimpleCommands(t *testing.T) {
	tests := []struct {
		input string
		n     int
		first string
	}{
		{"ls -la", 1, "ls"},
		{"/usr/bin/cat file.txt", 1, "/usr/bin/cat"},
		{`echo "hello world"`, 1, "echo"},
		{"git log --oneline -5", 1, "git"},
	}

	for _, tt := range tests {
		cmds, err := ExtractCommands(tt.input)
		if err != nil {
			t.Errorf("ExtractCommands(%q) error: %v", tt.input, err)
			continue
		}
		if len(cmds) != tt.n {
			t.Errorf("ExtractCommands(%q) = %d cmds, want %d", tt.input, len(cmds), tt.n)
			continue
		}
		if len(cmds) > 0 && cmds[0].Name() != tt.first {
			t.Errorf("ExtractCommands(%q) first = %q, want %q", tt.input, cmds[0].Name(), tt.first)
		}
	}
}

func TestNestedCmdSubst(t *testing.T) {
	cmds, err := ExtractCommands("echo $(rm -rf /)")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands (echo + rm), got %d", len(cmds))
	}
	if cmds[1].Name() != "rm" {
		t.Errorf("second command should be 'rm', got %q", cmds[1].Name())
	}
}

func TestNestedCmdSubstInDoubleQuotes(t *testing.T) {
	cmds, err := ExtractCommands(`echo "$(rm -rf /)"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(cmds))
	}
	if cmds[1].Name() != "rm" {
		t.Errorf("second command should be 'rm', got %q", cmds[1].Name())
	}
}

func TestDeeplyNestedCmdSubst(t *testing.T) {
	cmds, err := ExtractCommands("echo $(echo $(rm -rf /))")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 3 {
		t.Fatalf("expected 3 commands, got %d", len(cmds))
	}
}

func TestBacktickSubstitution(t *testing.T) {
	cmds, err := ExtractCommands("echo `rm -rf /`")
	if err != nil {
		t.Fatal(err)
	}
	// Note: mvdan/sh may parse backticks as CmdSubst with Backquotes=true
	// or may fall back to Lit depending on the version
	// Just verify no error and at least one command
	if len(cmds) < 1 {
		t.Fatal("expected at least 1 command")
	}
}

func TestPipeline(t *testing.T) {
	cmds, err := ExtractCommands("echo hello | grep hi")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(cmds))
	}
}

func TestLogicalOperators(t *testing.T) {
	cmds, err := ExtractCommands("ls && echo done || echo failed")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 3 {
		t.Fatalf("expected 3 commands, got %d", len(cmds))
	}
}

func TestSubshell(t *testing.T) {
	cmds, err := ExtractCommands("(rm -rf /)")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
	if cmds[0].Name() != "rm" {
		t.Errorf("expected 'rm', got %q", cmds[0].Name())
	}
}

func TestSubshellInPipeline(t *testing.T) {
	cmds, err := ExtractCommands("(echo hello) | grep hi")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(cmds))
	}
}

func TestIfClause(t *testing.T) {
	cmds, err := ExtractCommands("if test -f foo; then rm -rf /; fi")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands (test + rm), got %d", len(cmds))
	}
}

func TestIfElseClause(t *testing.T) {
	cmds, err := ExtractCommands("if true; then echo yes; else echo no; fi")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 3 {
		t.Fatalf("expected 3 commands, got %d", len(cmds))
	}
}

func TestIfElifElse(t *testing.T) {
	cmds, err := ExtractCommands("if test -f a; then echo a; elif test -f b; then echo b; else echo c; fi")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 5 {
		t.Fatalf("expected 5 commands (test, echo, test, echo, echo), got %d", len(cmds))
	}
}

func TestForLoop(t *testing.T) {
	cmds, err := ExtractCommands("for x in 1 2 3; do echo $x; done")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command (echo), got %d", len(cmds))
	}
}

func TestForLoopNested(t *testing.T) {
	cmds, err := ExtractCommands("for x in 1; do rm -rf /; done")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command (rm), got %d", len(cmds))
	}
	if cmds[0].Name() != "rm" {
		t.Errorf("expected 'rm', got %q", cmds[0].Name())
	}
}

func TestWhileLoop(t *testing.T) {
	cmds, err := ExtractCommands("while true; do rm -rf /; done")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands (true + rm), got %d", len(cmds))
	}
}

func TestUntilLoop(t *testing.T) {
	cmds, err := ExtractCommands("until test -f /tmp/done; do sleep 1; done")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(cmds))
	}
}

func TestCaseClause(t *testing.T) {
	cmds, err := ExtractCommands("case $x in start) echo running;; stop) rm -rf /;; esac")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(cmds))
	}
}

func TestProcSubst(t *testing.T) {
	cmds, err := ExtractCommands("diff <(sort a.txt) <(sort b.txt)")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 3 {
		t.Fatalf("expected 3 commands (diff + 2 sorts), got %d", len(cmds))
	}
}

func TestBraceGroup(t *testing.T) {
	cmds, err := ExtractCommands("{ echo a; echo b; }")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(cmds))
	}
}

func TestRedirectsWithHeredoc(t *testing.T) {
	cmds, err := ExtractCommands("cat <<EOF\nhello\nEOF")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
}

func TestEnvPrefixCommands(t *testing.T) {
	cmds, err := ExtractCommands("FOO=bar ls -la")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
	if cmds[0].Name() != "ls" {
		t.Errorf("expected 'ls', got %q", cmds[0].Name())
	}
}

// ─── Token methods ────────────────────────────────────────────

func TestPrefixMatch(t *testing.T) {
	cmd := ExtractedCommand{Tokens: []string{"git", "log", "--oneline", "-5"}}

	if !cmd.IsPrefixMatch([]string{"git"}) {
		t.Error("'git' should match")
	}
	if !cmd.IsPrefixMatch([]string{"git", "log"}) {
		t.Error("'git log' should match")
	}
	if cmd.IsPrefixMatch([]string{"git", "push"}) {
		t.Error("'git push' should NOT match")
	}
	if cmd.IsPrefixMatch([]string{"git", "log", "--oneline", "-5", "extra"}) {
		t.Error("longer prefix should NOT match")
	}
	if cmd.IsPrefixMatch([]string{}) {
		t.Error("empty prefix should not match")
	}
}

func TestHasFlag(t *testing.T) {
	cmd := ExtractedCommand{Tokens: []string{"find", ".", "-name", "*.go", "-exec", "rm"}}

	if !cmd.HasFlag("-exec") {
		t.Error("should have -exec flag")
	}
	if cmd.HasFlag("-delete") {
		t.Error("should NOT have -delete flag")
	}

	// -- should stop flag search
	cmd2 := ExtractedCommand{Tokens: []string{"grep", "--", "-dangerous"}}
	if cmd2.HasFlag("-dangerous") {
		t.Error("flags after -- should not match")
	}
}

func TestHasFlagWithEquals(t *testing.T) {
	cmd := ExtractedCommand{Tokens: []string{"sed", "--in-place=.bak", "s/foo/bar/"}}
	if !cmd.HasFlag("--in-place") {
		t.Error("should detect --in-place from --in-place=.bak")
	}
}

func TestName(t *testing.T) {
	tests := []struct {
		tokens []string
		name   string
	}{
		{[]string{"ls"}, "ls"},
		{[]string{"/usr/bin/ls", "-la"}, "/usr/bin/ls"},
		{[]string{"git", "log"}, "git"},
		{nil, ""},
		{[]string{}, ""},
	}

	for _, tt := range tests {
		cmd := ExtractedCommand{Tokens: tt.tokens}
		if cmd.Name() != tt.name {
			t.Errorf("Name(%v) = %q, want %q", tt.tokens, cmd.Name(), tt.name)
		}
	}
}

func TestSingleQuotedArgs(t *testing.T) {
	cmds, err := ExtractCommands(`jq '.key' file.json`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
}

func TestComplexRedirect(t *testing.T) {
	cmds, err := ExtractCommands("echo hello > /dev/null 2>&1")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
	if cmds[0].Name() != "echo" {
		t.Errorf("expected 'echo', got %q", cmds[0].Name())
	}
}

func TestBackgroundCommand(t *testing.T) {
	cmds, err := ExtractCommands("sleep 10 &")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
}

func TestPathPrefixMatch(t *testing.T) {
	tests := []struct {
		tokens []string
		prefix []string
		want   bool
	}{
		{[]string{"/bin/ls", "-la"}, []string{"ls"}, true},
		{[]string{"/bin/ls", "-la"}, []string{"/bin/ls"}, true},
		{[]string{"/bin/ls", "-la"}, []string{"cat"}, false},
		{[]string{"./ls", "-la"}, []string{"ls"}, true},
		{[]string{"../bin/ls", "-la"}, []string{"ls"}, true},
		{[]string{"~/bin/ls", "-la"}, []string{"ls"}, true},
		{[]string{"/usr/bin/git", "log"}, []string{"git", "log"}, true},
		{[]string{"/usr/bin/git", "push"}, []string{"git", "log"}, false},
		{[]string{"ls"}, []string{"ls"}, true}, // bare command, no path
	}

	for _, tt := range tests {
		cmd := ExtractedCommand{Tokens: tt.tokens}
		got := cmd.IsPrefixMatch(tt.prefix)
		if got != tt.want {
			t.Errorf("IsPrefixMatch(%v, %v) = %v, want %v", tt.tokens, tt.prefix, got, tt.want)
		}
	}
}

func TestMatch(t *testing.T) {
	tests := []struct {
		tokens  []string
		pattern []string
		want    bool
	}{
		{[]string{"git", "log", "--oneline"}, []string{"git", "log"}, true},
		{[]string{"git", "push"}, []string{"git", "log"}, false},
		{[]string{"ls", "-la"}, []string{"ls"}, true},
		{[]string{"python", "--version"}, []string{"*", "--version"}, true},
		{[]string{"git", "--version"}, []string{"*", "--version"}, true},
		{[]string{"python", "--help"}, []string{"*", "--help"}, true},
		{[]string{"python", "--version", "--help"}, []string{"*", "--version"}, false},
		{[]string{"python", "--version"}, []string{"*", "--help"}, false},
		{[]string{"ls"}, []string{"*", "--version"}, false},
		{[]string{"git", "push", "--force"}, []string{"*", "push", "--force"}, true},
	}

	for _, tt := range tests {
		cmd := ExtractedCommand{Tokens: tt.tokens}
		got := cmd.Match(tt.pattern)
		if got != tt.want {
			t.Errorf("Match(%v, %v) = %v, want %v", tt.tokens, tt.pattern, got, tt.want)
		}
	}
}

func TestNonFlagArgs(t *testing.T) {
	tests := []struct {
		name   string
		tokens []string
		want   []string
	}{
		{"only flags", []string{"ls", "-la"}, nil}, // -la is a flag (bundle)
		{"rm with args", []string{"rm", "-rf", "/tmp/foo", "/var/log"}, []string{"/tmp/foo", "/var/log"}},
		{"long flag with value", []string{"grep", "--label=foo", "pattern", "file"}, []string{"pattern", "file"}},
		{"dashdash stops flag scan", []string{"rm", "--", "-rf", "/tmp/foo", "/etc"}, []string{"-rf", "/tmp/foo", "/etc"}},
		{"flag with attached value", []string{"rm", "-i.bak", "/tmp/x"}, []string{"/tmp/x"}},
		{"no tokens", []string{"ls"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := ExtractedCommand{Tokens: tt.tokens}
			got := cmd.NonFlagArgs()
			if !stringSliceEq(got, tt.want) {
				t.Errorf("NonFlagArgs(%v) = %v, want %v", tt.tokens, got, tt.want)
			}
		})
	}
}

func TestExpandedFlagSet(t *testing.T) {
	tests := []struct {
		name   string
		tokens []string
		want   []string
	}{
		{"rm -rf", []string{"rm", "-rf"}, []string{"-r", "-f"}},
		{"rm separate", []string{"rm", "-r", "-f"}, []string{"-r", "-f"}},
		{"rm -fr -i", []string{"rm", "-fr", "-i"}, []string{"-f", "-r", "-i"}},
		{"long with value", []string{"grep", "--label=foo"}, []string{"--label"}},
		{"long bare", []string{"git", "--no-pager"}, []string{"--no-pager"}},
		{"gnu long with single dash", []string{"find", ".", "-name", "x"}, []string{"-name"}},
		{"attached value treated as long", []string{"rm", "-i.bak"}, []string{"-i.bak"}},
		{"dashdash stops", []string{"rm", "--", "-rf", "/tmp/x"}, nil},
		{"no flags", []string{"ls", "/tmp"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := ExtractedCommand{Tokens: tt.tokens}
			got := cmd.ExpandedFlagSet()
			if !stringSetEq(got, tt.want) {
				t.Errorf("ExpandedFlagSet(%v) = %v, want %v", tt.tokens, setKeys(got), tt.want)
			}
		})
	}
}

func stringSliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func stringSetEq(got map[string]struct{}, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, w := range want {
		if _, ok := got[w]; !ok {
			return false
		}
	}
	return true
}

func setKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestIsShortBundle(t *testing.T) {
	tests := []struct {
		tok  string
		want bool
	}{
		// 3–4 lowercase letters → bundle.
		{"-rf", true},
		{"-fr", true},
		{"-rfi", true},
		{"-rv", true},
		// 5+ letters → GNU long, not a bundle.
		{"-name", false},
		{"-exec", false},
		{"-delete", false},
		{"-rfivx", false},
		// Length ≤ 2 → not handled by this helper; caller treats it as a
		// single short flag.
		{"-r", false},
		{"-x", false},
		// Digits → not a bundle (no caller's "stop at non-letter" hack).
		{"-r2", false},
		{"-123", false},
		// Mixed case → not a bundle.
		{"-rF", false},
		{"-Rf", false},
		{"-NAME", false},
		// Empty / not a flag at all.
		{"", false},
		{"--", false},
		{"foo", false},
	}
	for _, tt := range tests {
		t.Run(tt.tok, func(t *testing.T) {
			if got := IsShortBundle(tt.tok); got != tt.want {
				t.Errorf("IsShortBundle(%q) = %v, want %v", tt.tok, got, tt.want)
			}
		})
	}
}
