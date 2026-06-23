package rules

import (
	"testing"

	"github.com/happyTonakai/permission-gate/internal/config"
	"github.com/happyTonakai/permission-gate/internal/verdict"
)

func allowList() []string {
	return []string{"ls", "cat", "echo", "grep", "git log", "git status", "find"}
}

func denyList() []string {
	return []string{"rm", "sudo"}
}

func askList() []string {
	return []string{"git push", "git commit"}
}

func denyFlags() map[string][]string {
	return map[string][]string{
		"find": {"-exec", "-delete"},
	}
}

func engine() *Engine {
	return New(&config.Config{}, allowList(), denyList(), askList(), denyFlags())
}

// ─── Basic tier tests ─────────────────────────────────────────

func TestAllow(t *testing.T) {
	result := engine().Evaluate("ls -la")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow, got %s", result.Final.Level)
	}
}

func TestDeny(t *testing.T) {
	result := engine().Evaluate("rm -rf /")
	if result.Final.Level != verdict.LevelDeny {
		t.Errorf("expected deny, got %s", result.Final.Level)
	}
}

func TestAsk(t *testing.T) {
	result := engine().Evaluate("git push origin main")
	if result.Final.Level != verdict.LevelAsk {
		t.Errorf("expected ask, got %s", result.Final.Level)
	}
}

func TestUnknownBecomesAsk(t *testing.T) {
	result := engine().Evaluate("some-weird-command")
	if result.Final.Level != verdict.LevelAsk {
		t.Errorf("expected ask for unknown, got %s", result.Final.Level)
	}
}

// ─── AST / nesting ────────────────────────────────────────────

func TestNestedCmdSubstDeny(t *testing.T) {
	result := engine().Evaluate("echo $(rm -rf /)")
	if result.Final.Level != verdict.LevelDeny {
		t.Errorf("expected deny for nested rm, got %s", result.Final.Level)
	}
}

func TestPipelineAllow(t *testing.T) {
	result := engine().Evaluate("ls -la | grep foo")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow, got %s", result.Final.Level)
	}
}

func TestPipelineWithDeny(t *testing.T) {
	result := engine().Evaluate("ls -la | sudo rm -rf /")
	if result.Final.Level != verdict.LevelDeny {
		t.Errorf("expected deny, got %s", result.Final.Level)
	}
}

// ─── Flag-level deny ──────────────────────────────────────────

func TestFlagDeny(t *testing.T) {
	result := engine().Evaluate("find . -name foo -exec rm {} \\;")
	if result.Final.Level != verdict.LevelDeny {
		t.Errorf("expected deny for find -exec, got %s", result.Final.Level)
	}
}

func TestFindWithoutDangerousFlags(t *testing.T) {
	result := engine().Evaluate("find . -name '*.go' -type f")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow for safe find, got %s", result.Final.Level)
	}
}

// ─── Subcommand prefix matching ───────────────────────────────

func TestGitLogAllowed(t *testing.T) {
	result := engine().Evaluate("git log --oneline -5")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow, got %s", result.Final.Level)
	}
}

func TestGitStatusAllowed(t *testing.T) {
	result := engine().Evaluate("git status --short")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow, got %s", result.Final.Level)
	}
}

func TestGitPushAsked(t *testing.T) {
	result := engine().Evaluate("git push origin main")
	if result.Final.Level != verdict.LevelAsk {
		t.Errorf("expected ask, got %s", result.Final.Level)
	}
}

// ─── Compound commands ────────────────────────────────────────

func TestLogicalAnd(t *testing.T) {
	result := engine().Evaluate("ls && echo done")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow, got %s", result.Final.Level)
	}
}

func TestLogicalAndWithDeny(t *testing.T) {
	result := engine().Evaluate("ls && rm -rf /")
	if result.Final.Level != verdict.LevelDeny {
		t.Errorf("expected deny, got %s", result.Final.Level)
	}
}

func TestMixedAskAndAllow(t *testing.T) {
	// ls (allow) && git push (ask) → overall ask
	result := engine().Evaluate("ls && git push")
	if result.Final.Level != verdict.LevelAsk {
		t.Errorf("expected ask, got %s", result.Final.Level)
	}
}

func TestMixedDenyAndAllow(t *testing.T) {
	// Deny wins over allow
	result := engine().Evaluate("ls && rm file && git push")
	if result.Final.Level != verdict.LevelDeny {
		t.Errorf("expected deny (rm beats ask), got %s", result.Final.Level)
	}
}

// ─── Edge cases ───────────────────────────────────────────────

func TestEmptyCommandIsAllow(t *testing.T) {
	result := engine().Evaluate("")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow for empty, got %s", result.Final.Level)
	}
}

func TestParseErrorIsAsk(t *testing.T) {
	// A shell we can't parse isn't necessarily dangerous — the user
	// knows what they meant. Falling back to ask lets them confirm
	// manually instead of silently denying.
	result := engine().Evaluate("echo 'unclosed")
	if result.Final.Level != verdict.LevelAsk {
		t.Errorf("expected ask for parse error, got %s", result.Final.Level)
	}
}

func TestJustComments(t *testing.T) {
	result := engine().Evaluate("# this is just a comment")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow for comment-only, got %s", result.Final.Level)
	}
}

func TestEnvPrefix(t *testing.T) {
	result := engine().Evaluate("FOO=bar ls -la")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow with env prefix, got %s", result.Final.Level)
	}
}

func TestSubshell(t *testing.T) {
	result := engine().Evaluate("(ls -la)")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow for subshell, got %s", result.Final.Level)
	}
}

func TestSubshellWithDeny(t *testing.T) {
	result := engine().Evaluate("(sudo ls)")
	if result.Final.Level != verdict.LevelDeny {
		t.Errorf("expected deny for subshell with sudo, got %s", result.Final.Level)
	}
}

// ─── If / for / while ─────────────────────────────────────────

func TestIfClauseAllow(t *testing.T) {
	e := New(&config.Config{}, []string{"test", "echo"}, nil, nil, nil)
	result := e.Evaluate("if test -f foo; then echo exists; fi")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow, got %s", result.Final.Level)
	}
}

func TestIfClauseWithDenyInside(t *testing.T) {
	e := New(&config.Config{}, []string{"test", "echo"}, []string{"rm"}, nil, nil)
	result := e.Evaluate("if test -f foo; then rm -rf /; fi")
	if result.Final.Level != verdict.LevelDeny {
		t.Errorf("expected deny, got %s", result.Final.Level)
	}
}

func TestForLoop(t *testing.T) {
	e := New(&config.Config{}, []string{"echo", "sleep"}, nil, nil, nil)
	result := e.Evaluate("for x in 1 2 3; do echo $x; done")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow, got %s", result.Final.Level)
	}
}

// ─── Config merging ───────────────────────────────────────────

func TestUserDenyOverridesBuiltinAllow(t *testing.T) {
	cfg := &config.Config{
		Deny: config.CommandRules{Commands: []string{"ls"}},
		GlobalRaw: config.RawConfig{
			Deny: config.CommandRules{Commands: []string{"ls"}},
		},
	}
	e := New(cfg, []string{"ls"}, nil, nil, nil)

	result := e.Evaluate("ls")
	if result.Final.Level != verdict.LevelDeny {
		t.Errorf("expected deny (user config overrides builtin), got %s", result.Final.Level)
	}
}

func TestUserAllowExtendsBuiltin(t *testing.T) {
	cfg := &config.Config{
		Allow: config.CommandRules{Commands: []string{"my-tool"}},
		GlobalRaw: config.RawConfig{
			Allow: config.CommandRules{Commands: []string{"my-tool"}},
		},
	}
	e := New(cfg, nil, nil, nil, nil)

	assertAllowed(t, e, "my-tool")
	assertAsked(t, e, "ls") // not in builtin or user allow
}

func TestUserFlagRules(t *testing.T) {
	cfg := &config.Config{
		Deny: config.CommandRules{
			Flags: map[string][]string{"grep": {"--dangerous"}},
		},
	}
	e := New(cfg, []string{"grep"}, nil, nil, map[string][]string{
		"grep": {"-e", "-n"},
	})

	// builtin flags still deny
	assertDenied(t, e, "grep -e pattern file")
	// user-added flags also deny
	assertDenied(t, e, "grep --dangerous file")
}

// ─── Helpers ──────────────────────────────────────────────────

func assertAllowed(t *testing.T, e *Engine, cmd string) {
	t.Helper()
	result := e.Evaluate(cmd)
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow for %q, got %s", cmd, result.Final.Level)
	}
}

func assertDenied(t *testing.T, e *Engine, cmd string) {
	t.Helper()
	result := e.Evaluate(cmd)
	if result.Final.Level != verdict.LevelDeny {
		t.Errorf("expected deny for %q, got %s", cmd, result.Final.Level)
	}
}

func assertAsked(t *testing.T, e *Engine, cmd string) {
	t.Helper()
	result := e.Evaluate(cmd)
	if result.Final.Level != verdict.LevelAsk {
		t.Errorf("expected ask for %q, got %s", cmd, result.Final.Level)
	}
}
