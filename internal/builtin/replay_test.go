package builtin

import (
	"fmt"
	"strings"
	"testing"

	"github.com/happyTonakai/permission-gate/internal/config"
	"github.com/happyTonakai/permission-gate/internal/rules"
	"github.com/happyTonakai/permission-gate/internal/verdict"
)

// Replay commands from real Pi agent permission-gate log
// and show how our pgate would classify them.
func TestReplayLog(t *testing.T) {
	engine, err := rules.New(&config.Config{}, config.MergePrepend, Allow(), Deny(), Ask(), DenyFlags())
	if err != nil {
		t.Fatal(err)
	}

	commands := []string{
		// === Allow in original log ===
		`ls /Users/hanzerui/joyspace/biliradio/biliradio/`,
		`rg -n "print|logger|logging" /Users/hanzerui/joyspace/biliradio/biliradio/ --type py | head -50`,
		`curl -s "http://localhost:3737/api/search" 2>&1 | head -100`,
		`grep -rn "pushed_at" --include="*.go" 2>&1 | grep -v _test.go`,
		`git log --oneline --all --since="30 days ago" | head -40`,
		`git show 29f9c64 --stat`,
		`head -20 /Users/hanzerui/joyspace/biliradio/biliradio_cron.log`,
		`cat /Users/hanzerui/joyspace/biliradio/logs/biliradio.log`,
		`which sqlite3`,
		`git status --short`,
		`git diff --stat HEAD biliradio/__main__.py`,
		`go build ./... 2>&1 | head -40`,
		`go vet ./internal/database/ ./internal/feishu/ 2>&1`,
		`go test ./internal/database/ -count=1 2>&1 | tail -30`,
		`uv run ruff check biliradio/`,
		`ls -la ~/.config/paperagent/*.log 2>&1`,
		`ps aux | grep -i paperagent`,
		`wc -l /Users/hanzerui/joyspace/biliradio/logs/biliradio.log`,
		`file /Users/hanzerui/joyspace/biliradio/biliradio_cron.log`,
		`echo "hello world"`,
		`echo "==="`,
		`date`,

		// === Ask in original log (sqlite3 queries, etc) ===
		`sqlite3 ~/.config/paperagent/zenflow.db "SELECT * FROM articles LIMIT 5;"`,
		`sqlite3 -header -column ~/.config/paperagent/zenflow.db "SELECT id, status FROM articles;"`,
		`journalctl --user -u paperagent --since "2 days ago" 2>/dev/null | tail -50`,
		`launchctl list 2>&1 | grep -i paper | head`,

		// === Deny in original log ===
		`rm -rf /Users/hanzerui/joyspace/biliradio/logs/*`,

		// === Extra edge cases we care about ===
		`uv run python -c "print(1+1)"`,
		`uvx ruff check biliradio/`,
		`sed -i.bak "s/foo/bar/" file`,
		`git stash push internal/database/operations.go`,
		`git stash pop`,
		`git push origin main`,
		`git commit -m "fix bug"`,
		`docker ps`,
		`docker build -t myimage .`,
		`kubectl get pods`,
		`kubectl delete pod foo`,
		`npm install`,
		`pip install requests`,
		`cargo build --release`,
		`python -c "import os; os.remove('file')"`,
		`chmod +x script.sh`,
		`chmod -R 777 /some/dir`,
		`sudo apt-get update`,
		`gh pr create --title "fix" --body "desc"`,

		// Commands that should be ASK (not in any list)
		`some-obscure-tool --do-dangerous-stuff`,
		`mc cp /local /remote/bucket`,
		`rclone sync /local remote:backup`,

		// Commands with nested danger
		`echo $(echo $(rm -rf /))`,
		`find . -name "*.go" -delete`,
		`find . -type f -name "*.tmp"`,
		// Regression: -print / -printf must stay allow (output-only flags).
		`find . -name "*.go" -print`,
		`find . -name "*.go" -printf "%p\n"`,
		// Regression: multi-predicate find using -o (OR) and -prune must
		// not be misflagged by the deny spec -ok (which IsShortBundle
		// would expand to "-o -k" and falsely match the -o flag).
		`find . -path ./skip -prune -o -path ./also-skip -prune -o -type f -name "*.go" -print`,
		`for f in *.txt; do cat $f; done`,
		`if test -f foo; then echo exists; else echo not; fi`,
		`(ls -la | grep foo) && echo done`,
	}

	results := [][3]string{}
	for _, cmd := range commands {
		result := engine.Evaluate(cmd)
		var verdictStr string
		switch result.Final.Level {
		case verdict.LevelAllow:
			verdictStr = "allow"
		case verdict.LevelDeny:
			verdictStr = "deny "
		case verdict.LevelAsk:
			verdictStr = "ask  "
		}
		segDetails := []string{}
		for _, seg := range result.Segments {
			var s string
			switch seg.Verdict.Level {
			case verdict.LevelAllow:
				s = "A"
			case verdict.LevelDeny:
				s = "D"
			case verdict.LevelAsk:
				s = "?"
			}
			segDetails = append(segDetails, fmt.Sprintf("%s:%s", s, seg.Command))
		}
		results = append(results, [3]string{verdictStr, shortCmd(cmd), strings.Join(segDetails, " | ")})
	}

	fmt.Println()
	fmt.Println("Pi agent permission-gate log replay — pgate classification")
	fmt.Println(strings.Repeat("=", 80))

	for _, r := range results {
		fmt.Printf("  %s  %-60s  %s\n", r[0], r[1], r[2])
	}
}

// TestFindFlagDenial guards two regressions in built-in find flag-deny
// rules:
//
//  1. Output-only flags (-print, -printf) must NOT trigger deny. They
//     cannot execute commands or delete files; -print is literally
//     find's default action.
//
//  2. A multi-predicate find using -o (OR) and -prune must NOT be
//     misflagged by the deny spec -ok. The deny spec "-ok" used to be
//     expanded as the short-option bundle "-o -k" and falsely match the
//     -o operator that appears in nearly every non-trivial find
//     expression. flagMatches now requires ALL bundled letters to be
//     present in the command's flag set, so "-ok" no longer matches a
//     command that only has "-o" (no "-k").
func TestFindFlagDenial(t *testing.T) {
	engine, err := rules.New(&config.Config{}, config.MergePrepend, Allow(), Deny(), Ask(), DenyFlags())
	if err != nil {
		t.Fatal(err)
	}

	allow := []string{
		`find . -name "*.go" -print`,
		`find . -name "*.go" -printf "%p\n"`,
		`find . -path ./skip -prune -o -path ./also -prune -o -type f -name "*.go" -print`,
		// Garden-path: -o with no -k. Catches the regression where the
		// deny spec "-ok" was being expanded as the bundle "-o -k" and
		// matching any find expression using the -o (OR) operator.
		// find has no -k flag in practice, but the test stays valid
		// regardless.
		`find . -name "*.go" -o -name "*.java"`,
		`find . -o -name "*.go" -print`,
	}
	for _, cmd := range allow {
		if v := engine.Evaluate(cmd).Final.Level; v != verdict.LevelAllow {
			t.Errorf("expected allow for %q, got %s (%s)", cmd, v, v)
		}
	}

	deny := []string{
		`find . -name "*.go" -delete`,
		`find . -name "*.go" -exec rm {} \;`,
		`find . -name "*.go" -execdir rm {} \;`,
		`find . -name "*.go" -ok rm {} \;`,
		`find . -name "*.go" -okdir rm {} \;`,
	}
	for _, cmd := range deny {
		if v := engine.Evaluate(cmd).Final.Level; v != verdict.LevelDeny {
			t.Errorf("expected deny for %q, got %s (%s)", cmd, v, v)
		}
	}
}

func shortCmd(cmd string) string {
	if len(cmd) > 58 {
		return cmd[:55] + "..."
	}
	return cmd
}
