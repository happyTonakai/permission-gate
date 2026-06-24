package rules

import (
	"os"
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

func engine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(&config.Config{}, config.MergePrepend, allowList(), denyList(), askList(), denyFlags())
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func newEngine(t *testing.T, cfg *config.Config, mode config.MergeMode, allow, deny, ask []string, denyFlags map[string][]string) *Engine {
	t.Helper()
	e, err := New(cfg, mode, allow, deny, ask, denyFlags)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// ─── Basic tier tests ─────────────────────────────────────────

func TestAllow(t *testing.T) {
	result := engine(t).Evaluate("ls -la")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow, got %s", result.Final.Level)
	}
}

func TestDeny(t *testing.T) {
	result := engine(t).Evaluate("rm -rf /")
	if result.Final.Level != verdict.LevelDeny {
		t.Errorf("expected deny, got %s", result.Final.Level)
	}
}

func TestAsk(t *testing.T) {
	result := engine(t).Evaluate("git push origin main")
	if result.Final.Level != verdict.LevelAsk {
		t.Errorf("expected ask, got %s", result.Final.Level)
	}
}

func TestUnknownBecomesAsk(t *testing.T) {
	result := engine(t).Evaluate("some-weird-command")
	if result.Final.Level != verdict.LevelAsk {
		t.Errorf("expected ask for unknown, got %s", result.Final.Level)
	}
}

// ─── AST / nesting ────────────────────────────────────────────

func TestNestedCmdSubstDeny(t *testing.T) {
	result := engine(t).Evaluate("echo $(rm -rf /)")
	if result.Final.Level != verdict.LevelDeny {
		t.Errorf("expected deny for nested rm, got %s", result.Final.Level)
	}
}

func TestPipelineAllow(t *testing.T) {
	result := engine(t).Evaluate("ls -la | grep foo")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow, got %s", result.Final.Level)
	}
}

func TestPipelineWithDeny(t *testing.T) {
	result := engine(t).Evaluate("ls -la | sudo rm -rf /")
	if result.Final.Level != verdict.LevelDeny {
		t.Errorf("expected deny, got %s", result.Final.Level)
	}
}

// ─── Flag-level deny ──────────────────────────────────────────

func TestFlagDeny(t *testing.T) {
	result := engine(t).Evaluate("find . -name foo -exec rm {} \\;")
	if result.Final.Level != verdict.LevelDeny {
		t.Errorf("expected deny for find -exec, got %s", result.Final.Level)
	}
}

func TestFindWithoutDangerousFlags(t *testing.T) {
	result := engine(t).Evaluate("find . -name '*.go' -type f")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow for safe find, got %s", result.Final.Level)
	}
}

// TestEmptyDenyFlagListDoesNotDenyCommand guards against a regression where
// a builtin deny-flag entry with an empty flag list (e.g. "git": {}) was
// converted into a virtual deny spec that matched every invocation of the
// command — because empty IncludeFlags means "no constraint", not "match
// all". Commands with an empty deny-flag list must be left untouched.
func TestEmptyDenyFlagListDoesNotDenyCommand(t *testing.T) {
	denyFlagsWithEmpty := map[string][]string{
		"git":  {},        // empty list — must NOT deny plain `git status`
		"find": {"-exec"}, // real list — must still deny
	}
	e := newEngine(t, &config.Config{}, config.MergePrepend, []string{"git", "ls", "find"}, nil, nil, denyFlagsWithEmpty)

	assertAllowed(t, e, "git status")
	assertAllowed(t, e, "git status -s")
	assertAllowed(t, e, "git diff")
	assertAllowed(t, e, "git commit -m hi")
	assertAllowed(t, e, "ls -la")
	assertDenied(t, e, "find . -exec rm {} \\;")
	assertAllowed(t, e, "find . -name '*.go'")
}

// ─── Subcommand prefix matching ───────────────────────────────

func TestGitLogAllowed(t *testing.T) {
	result := engine(t).Evaluate("git log --oneline -5")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow, got %s", result.Final.Level)
	}
}

func TestGitStatusAllowed(t *testing.T) {
	result := engine(t).Evaluate("git status --short")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow, got %s", result.Final.Level)
	}
}

func TestGitPushAsked(t *testing.T) {
	result := engine(t).Evaluate("git push origin main")
	if result.Final.Level != verdict.LevelAsk {
		t.Errorf("expected ask, got %s", result.Final.Level)
	}
}

// ─── Compound commands ────────────────────────────────────────

func TestLogicalAnd(t *testing.T) {
	result := engine(t).Evaluate("ls && echo done")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow, got %s", result.Final.Level)
	}
}

func TestLogicalAndWithDeny(t *testing.T) {
	result := engine(t).Evaluate("ls && rm -rf /")
	if result.Final.Level != verdict.LevelDeny {
		t.Errorf("expected deny, got %s", result.Final.Level)
	}
}

func TestMixedAskAndAllow(t *testing.T) {
	// ls (allow) && git push (ask) → overall ask
	result := engine(t).Evaluate("ls && git push")
	if result.Final.Level != verdict.LevelAsk {
		t.Errorf("expected ask, got %s", result.Final.Level)
	}
}

func TestMixedDenyAndAllow(t *testing.T) {
	// Deny wins over allow
	result := engine(t).Evaluate("ls && rm file && git push")
	if result.Final.Level != verdict.LevelDeny {
		t.Errorf("expected deny (rm beats ask), got %s", result.Final.Level)
	}
}

// ─── Edge cases ───────────────────────────────────────────────

func TestEmptyCommandIsAllow(t *testing.T) {
	result := engine(t).Evaluate("")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow for empty, got %s", result.Final.Level)
	}
}

func TestParseErrorIsAsk(t *testing.T) {
	// A shell we can't parse isn't necessarily dangerous — the user
	// knows what they meant. Falling back to ask lets them confirm
	// manually instead of silently denying.
	result := engine(t).Evaluate("echo 'unclosed")
	if result.Final.Level != verdict.LevelAsk {
		t.Errorf("expected ask for parse error, got %s", result.Final.Level)
	}
}

func TestJustComments(t *testing.T) {
	result := engine(t).Evaluate("# this is just a comment")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow for comment-only, got %s", result.Final.Level)
	}
}

func TestEnvPrefix(t *testing.T) {
	result := engine(t).Evaluate("FOO=bar ls -la")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow with env prefix, got %s", result.Final.Level)
	}
}

func TestSubshell(t *testing.T) {
	result := engine(t).Evaluate("(ls -la)")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow for subshell, got %s", result.Final.Level)
	}
}

func TestSubshellWithDeny(t *testing.T) {
	result := engine(t).Evaluate("(sudo ls)")
	if result.Final.Level != verdict.LevelDeny {
		t.Errorf("expected deny for subshell with sudo, got %s", result.Final.Level)
	}
}

// ─── If / for / while ─────────────────────────────────────────

func TestIfClauseAllow(t *testing.T) {
	e := newEngine(t, &config.Config{}, config.MergePrepend, []string{"test", "echo"}, nil, nil, nil)
	result := e.Evaluate("if test -f foo; then echo exists; fi")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow, got %s", result.Final.Level)
	}
}

func TestIfClauseWithDenyInside(t *testing.T) {
	e := newEngine(t, &config.Config{}, config.MergePrepend, []string{"test", "echo"}, []string{"rm"}, nil, nil)
	result := e.Evaluate("if test -f foo; then rm -rf /; fi")
	if result.Final.Level != verdict.LevelDeny {
		t.Errorf("expected deny, got %s", result.Final.Level)
	}
}

func TestForLoop(t *testing.T) {
	e := newEngine(t, &config.Config{}, config.MergePrepend, []string{"echo", "sleep"}, nil, nil, nil)
	result := e.Evaluate("for x in 1 2 3; do echo $x; done")
	if result.Final.Level != verdict.LevelAllow {
		t.Errorf("expected allow, got %s", result.Final.Level)
	}
}

// ─── Config merging ───────────────────────────────────────────

func TestUserDenyOverridesBuiltinAllow(t *testing.T) {
	cfg := &config.Config{
		GlobalRaw: config.RawConfig{
			Deny: config.RawRules{Commands: []any{"ls"}},
		},
	}
	e := newEngine(t, cfg, config.MergePrepend, []string{"ls"}, nil, nil, nil)

	result := e.Evaluate("ls")
	if result.Final.Level != verdict.LevelDeny {
		t.Errorf("expected deny (user config overrides builtin), got %s", result.Final.Level)
	}
}

func TestUserAllowExtendsBuiltin(t *testing.T) {
	cfg := &config.Config{
		GlobalRaw: config.RawConfig{
			Allow: config.RawRules{Commands: []any{"my-tool"}},
		},
	}
	e := newEngine(t, cfg, config.MergePrepend, nil, nil, nil, nil)

	assertAllowed(t, e, "my-tool")
	assertAsked(t, e, "ls") // not in builtin or user allow
}

func TestUserFlagRules(t *testing.T) {
	cfg := &config.Config{
		Deny: config.CommandRules{
			Flags: map[string][]string{"grep": {"--dangerous"}},
		},
	}
	e := newEngine(t, cfg, config.MergePrepend, []string{"grep"}, nil, nil, map[string][]string{
		"grep": {"-e", "-n"},
	})

	// builtin flags still deny
	assertDenied(t, e, "grep -e pattern file")
	// user-added flags also deny
	assertDenied(t, e, "grep --dangerous file")
}

// ─── Refined specs: include_flags / exclude_flags ───────────────

func TestIncludeFlagsAnyOf(t *testing.T) {
	cfg := &config.Config{
		GlobalRaw: config.RawConfig{
			Allow: config.RawRules{Commands: []any{
				map[string]any{"cmd": "rm", "include_flags": []any{"-f", "-rf", "-r"}},
			}},
		},
	}
	e := newEngine(t, cfg, config.MergePrepend, nil, nil, nil, nil)

	// `-f`, `-rf`, `-r` each satisfy the include constraint.
	assertAllowed(t, e, "rm -f /tmp/foo")
	assertAllowed(t, e, "rm -rf /tmp/foo")
	assertAllowed(t, e, "rm -r /tmp/foo")

	// No matching flag → spec does not match → fall through to unknown → ask.
	assertAsked(t, e, "rm /tmp/foo")
}

func TestIncludeFlagsBundleExpansion(t *testing.T) {
	// Spec written as `-rf` should still match commands that supply the
	// individual letters, thanks to short-option bundle expansion.
	cfg := &config.Config{
		GlobalRaw: config.RawConfig{
			Allow: config.RawRules{Commands: []any{
				map[string]any{"cmd": "rm", "include_flags": []any{"-rf"}},
			}},
		},
	}
	e := newEngine(t, cfg, config.MergePrepend, nil, nil, nil, nil)

	assertAllowed(t, e, "rm -rf /tmp/foo")
	assertAllowed(t, e, "rm -r /tmp/foo") // -r is part of -rf bundle
	assertAllowed(t, e, "rm -f /tmp/foo") // -f is part of -rf bundle
	assertAllowed(t, e, "rm -fr /tmp/foo")
	assertAsked(t, e, "rm -i /tmp/foo") // -i not in bundle
}

func TestExcludeFlagsNoneOf(t *testing.T) {
	cfg := &config.Config{
		GlobalRaw: config.RawConfig{
			Allow: config.RawRules{Commands: []any{
				map[string]any{"cmd": "rm", "exclude_flags": []any{"--no-preserve-root"}},
			}},
		},
	}
	e := newEngine(t, cfg, config.MergePrepend, nil, nil, nil, nil)

	assertAllowed(t, e, "rm -rf /tmp/foo")
	assertAsked(t, e, "rm --no-preserve-root -rf /tmp/foo")
}

// ─── Refined specs: include_args / exclude_args ────────────────

func TestIncludeArgsAllUnder(t *testing.T) {
	cfg := &config.Config{
		GlobalRaw: config.RawConfig{
			Allow: config.RawRules{Commands: []any{
				map[string]any{
					"cmd":          "rm",
					"include_args": []any{"/tmp", "/private/tmp"},
				},
			}},
		},
	}
	e := newEngine(t, cfg, config.MergePrepend, nil, nil, nil, nil)

	assertAllowed(t, e, "rm /tmp/foo")
	assertAllowed(t, e, "rm /tmp/a/b/c.txt")
	assertAllowed(t, e, "rm /private/tmp/x")
	// Anything outside /tmp is unknown → ask.
	assertAsked(t, e, "rm /etc/passwd")
	assertAsked(t, e, "rm /var/log")
}

func TestIncludeArgsAllUnder_MultiArgRequiresAllMatch(t *testing.T) {
	cfg := &config.Config{
		GlobalRaw: config.RawConfig{
			Allow: config.RawRules{Commands: []any{
				map[string]any{
					"cmd":          "rm",
					"include_args": []any{"/tmp"},
				},
			}},
		},
	}
	e := newEngine(t, cfg, config.MergePrepend, nil, nil, nil, nil)

	// Single arg under /tmp → allow.
	assertAllowed(t, e, "rm /tmp/foo")
	// Mixed: one under /tmp, one not → all-under fails → ask.
	assertAsked(t, e, "rm /tmp/foo /etc/passwd")
}

func TestIncludeArgsPathTraversal(t *testing.T) {
	cfg := &config.Config{
		GlobalRaw: config.RawConfig{
			Allow: config.RawRules{Commands: []any{
				map[string]any{
					"cmd":          "rm",
					"include_args": []any{"/tmp"},
				},
			}},
		},
	}
	e := newEngine(t, cfg, config.MergePrepend, nil, nil, nil, nil)

	// /tmp/../etc normalizes to /etc — must not match /tmp.
	assertAsked(t, e, "rm /tmp/../etc")
	// /tmp/. normalizes to /tmp — should still match (path equals prefix).
	assertAllowed(t, e, "rm /tmp/.")
}

func TestExcludeArgsNonePrefix(t *testing.T) {
	cfg := &config.Config{
		GlobalRaw: config.RawConfig{
			Allow: config.RawRules{Commands: []any{
				map[string]any{
					"cmd":          "rm",
					"exclude_args": []any{"/etc", "/var", "~"},
				},
			}},
		},
	}
	e := newEngine(t, cfg, config.MergePrepend, nil, nil, nil, nil)

	assertAllowed(t, e, "rm /tmp/foo")
	assertAllowed(t, e, "rm /home/user/x")
	// Anything under /etc, /var, or ~ makes the spec not match → fall through.
	assertAsked(t, e, "rm /etc/passwd")
	assertAsked(t, e, "rm /var/log/messages")
	// ~ expands to home dir; if home is /Users/me, ~/foo lives under ~.
	if home, err := os.UserHomeDir(); err == nil {
		assertAsked(t, e, "rm "+home+"/foo")
	}
}

func TestDashDashTerminatesFlags(t *testing.T) {
	cfg := &config.Config{
		GlobalRaw: config.RawConfig{
			Allow: config.RawRules{Commands: []any{
				map[string]any{
					"cmd":          "rm",
					"include_args": []any{"/tmp"},
				},
			}},
		},
	}
	e := newEngine(t, cfg, config.MergePrepend, nil, nil, nil, nil)

	// After `--`, -rf is positional (a literal file named "-rf"),
	// so include_args checking sees both /tmp/foo and -rf as args.
	// `-rf` doesn't live under /tmp → all-under fails → ask.
	assertAsked(t, e, "rm -- -rf /tmp/foo")

	// Without `--`, -rf is a flag and /etc is a positional arg outside /tmp.
	assertAsked(t, e, "rm -rf /etc")
}

func TestExcludeBeatsInclude(t *testing.T) {
	// Both fields configured; exclude hit fails the whole spec.
	cfg := &config.Config{
		GlobalRaw: config.RawConfig{
			Allow: config.RawRules{Commands: []any{
				map[string]any{
					"cmd":           "rm",
					"include_flags": []any{"-rf"},
					"exclude_args":  []any{"/etc"},
				},
			}},
		},
	}
	e := newEngine(t, cfg, config.MergePrepend, nil, nil, nil, nil)

	// /tmp + -rf: include_args is empty so trivially OK → allow.
	assertAllowed(t, e, "rm -rf /tmp/foo")
	// /etc + -rf: include_flags hit, but exclude_args hit → spec fails → ask.
	assertAsked(t, e, "rm -rf /etc/passwd")
}

// ─── Refined specs across tiers ───────────────────────────────

func TestRefinedSpecsApplyToDenyToo(t *testing.T) {
	// A refined spec in [deny] should narrow the deny rule to a subset.
	cfg := &config.Config{
		GlobalRaw: config.RawConfig{
			Deny: config.RawRules{Commands: []any{
				map[string]any{
					"cmd":          "rm",
					"exclude_args": []any{"/tmp"},
				},
			}},
		},
	}
	e := newEngine(t, cfg, config.MergePrepend, nil, nil, nil, nil)

	// /etc: deny spec matches (no /tmp arg) → deny.
	assertDenied(t, e, "rm /etc/passwd")
	// /tmp/foo: deny spec does not match (exclude_args hit) → no deny here,
	// unknown rm → ask.
	assertAsked(t, e, "rm /tmp/foo")
}

func TestRefinedSpecsInAsk(t *testing.T) {
	cfg := &config.Config{
		GlobalRaw: config.RawConfig{
			Ask: config.RawRules{Commands: []any{
				map[string]any{
					"cmd":          "git",
					"include_args": []any{"/tmp"},
				},
			}},
		},
	}
	// Use a builtin allow that does NOT cover `git`, so the ask spec is the
	// only rule that can match.
	e := newEngine(t, cfg, config.MergePrepend, []string{"echo"}, nil, nil, nil)

	// git commands outside /tmp: ask spec doesn't match (no /tmp arg),
	// builtin doesn't cover git → unknown → ask.
	assertAsked(t, e, "git reset --hard")
	// git commands inside /tmp hit the ask spec → ask.
	result := e.Evaluate("git reset /tmp/old-commit")
	if result.Final.Level != verdict.LevelAsk {
		t.Errorf("expected ask, got %s", result.Final.Level)
	}
}

// ─── Realistic narrow-channel scenario ─────────────────────────

// TestNarrowChannel shows the canonical way to carve out a /tmp-only window
// for `rm` under prepend mode: pair a refined deny (matches everything
// *except* /tmp) with a refined allow (matches /tmp). Both rules live in
// the user's [deny] / [allow] sections, which the engine emits into the
// merged pattern list in that order. The first spec to match wins:
//   - `rm /etc/passwd`  → user deny matches → deny
//   - `rm /tmp/foo`     → user deny doesn't match (exclude) → user allow matches → allow
//   - `rm /tmp /etc`    → user deny matches (because /etc arg is not under /tmp) → deny
func TestNarrowChannel(t *testing.T) {
	cfg := &config.Config{
		GlobalRaw: config.RawConfig{
			Deny: config.RawRules{Commands: []any{
				map[string]any{
					"cmd":          "rm",
					"exclude_args": []any{"/tmp", "/private/tmp"},
				},
			}},
			Allow: config.RawRules{Commands: []any{
				map[string]any{
					"cmd":          "rm",
					"include_args": []any{"/tmp", "/private/tmp"},
				},
			}},
		},
	}
	e := newEngine(t, cfg, config.MergePrepend, nil, nil, nil, nil)

	assertDenied(t, e, "rm /etc/passwd")
	assertAllowed(t, e, "rm /tmp/foo")
	assertAllowed(t, e, "rm -rf /tmp/foo")
	assertAsked(t, e, "rm /tmp/foo /etc/passwd") // mixed → both deny and allow specs miss → ask
	assertDenied(t, e, "rm /home/user/x")        // deny matches: not under /tmp, so exclude doesn't trigger
}

// TestNarrowChannel_AppendMode shows that under append mode the same
// configuration behaves differently: builtin deny `rm` runs before user
// allow, so even /tmp rm is denied. This is the documented difference
// between prepend and append.
func TestNarrowChannel_AppendMode(t *testing.T) {
	cfg := &config.Config{
		GlobalRaw: config.RawConfig{
			Deny: config.RawRules{Commands: []any{
				map[string]any{
					"cmd":          "rm",
					"exclude_args": []any{"/tmp", "/private/tmp"},
				},
			}},
			Allow: config.RawRules{Commands: []any{
				map[string]any{
					"cmd":          "rm",
					"include_args": []any{"/tmp", "/private/tmp"},
				},
			}},
		},
	}
	// In append mode, builtin rules run first. Builtin deny `rm` catches
	// everything, regardless of user refinements.
	e := newEngine(t, cfg, config.MergeAppend, nil, []string{"rm"}, nil, nil)

	assertDenied(t, e, "rm -rf /tmp/foo") // builtin deny wins
	assertDenied(t, e, "rm /etc/passwd")
}

// TestNarrowChannel_OverwriteMode demonstrates that overwrite mode drops
// the builtin deny entirely; the user's narrow-channel spec now works.
// In overwrite mode, user config is loaded from the project file
// (ProjectRaw), which is the documented escape hatch for fully overriding
// the built-in rules.
func TestNarrowChannel_OverwriteMode(t *testing.T) {
	cfg := &config.Config{
		ProjectRaw: config.RawConfig{
			Deny: config.RawRules{Commands: []any{
				map[string]any{
					"cmd":          "rm",
					"exclude_args": []any{"/tmp", "/private/tmp"},
				},
			}},
			Allow: config.RawRules{Commands: []any{
				map[string]any{
					"cmd":          "rm",
					"include_args": []any{"/tmp", "/private/tmp"},
				},
			}},
		},
	}
	e := newEngine(t, cfg, config.MergeOverwrite, nil, []string{"rm"}, nil, nil)

	assertDenied(t, e, "rm /etc/passwd")
	assertAllowed(t, e, "rm -rf /tmp/foo") // builtin deny is dropped; user allow wins
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
