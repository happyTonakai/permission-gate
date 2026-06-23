# Permission Gate

AST-based bash command permission gate. Parses shell commands into an AST, then evaluates each command segment against a three-tier allow / deny / ask rule engine.

Built on [`mvdan.cc/sh/v3`](https://github.com/mvdan/sh) for shell syntax parsing.

## How it works

```
User input → mvdan/sh AST → command extraction → rule matching → verdict
```

Every command is tokenized and checked against three lists:

| Tier    | Behavior              |
| ------- | --------------------- |
| Allow   | Auto-approved         |
| Deny    | Auto-blocked          |
| Ask     | Prompt user           |

If a command doesn't match any list, it defaults to **Ask** (safe by default).

For compound commands (pipes, `&&`, `||`, subshells, `if`/`for`/`while`), each segment is evaluated individually. The strictest verdict wins: one deny makes the whole command deny.

### Flag-level deny

Beyond whole-command rules, dangerous flags on safe commands can be denied:

```toml
[rules.deny]
flags = { find = ["-exec", "-delete"] }
```

This allows `find . -name '*.go'` but blocks `find . -exec rm {} \;`.

## Installation

```bash
go install github.com/happyTonakai/permission-gate/cmd/pgate@latest
```

Or build from source:

```bash
git clone https://github.com/happyTonakai/permission-gate.git
cd permission-gate
go build -o pgate ./cmd/pgate
```

## Usage

### Check a command

```bash
pgate check "rm -rf /"
# → deny: denied by pattern "rm"

pgate check "ls -la"
# → allow: allowed by pattern "ls"

pgate check "git push origin main"
# → ask: ask by pattern "git push"

pgate check --json "echo hello | grep world"
# → JSON output with per-segment verdicts

pgate check --detail "echo hello | grep world"
# → Detailed output with matched patterns
```

### Read from stdin

```bash
echo "curl http://example.com" | pgate check
```

### Init config

```bash
pgate init
# Creates ~/.config/permission-gate/config.toml
```

### Install hooks

```bash
pgate hook install claude-code
# Installs shell hook to ~/.claude/hooks/permission-gate.sh
```

## Configuration

User config is TOML, merged with built-in rules:

**Global:** `~/.config/permission-gate/config.toml`
**Project-level:** `.permission-gate.toml` (project directory)

```toml
[allow]
commands = ["my-tool", "kubectl get"]
flags = { kubectl = ["get"] }

[deny]
commands = ["sudo", "dangerous-command"]
flags = { curl = ["--output", "-o"], find = ["-exec", "-delete"] }

[ask]
commands = ["git push", "git commit", "kubectl delete"]

[profile]
merge = "append"  # prepend | append | overwrite
```

### Merge modes

| Mode      | Behavior                                         |
| --------- | ------------------------------------------------ |
| `prepend` | User rules checked first (user can override deny) |
| `append`  | Built-in rules checked first (default)            |
| `overwrite` | Built-in rules completely replaced             |

## Built-in commands

Permission Gate ships with ~10,000 built-in allow patterns covering:

- File operations: `ls`, `cat`, `echo`, `find`, `grep`, `head`, `tail`
- Version control: `git log`, `git status`, `git diff` (read-only), `git push` (ask)
- Development: `go build`, `npm install`, `pip`, `cargo`, `docker ps`
- System: `uname`, `df`, `du`, `ps`, `uptime`
- And many more — generated from the [safe-chains](https://github.com/michaeldhopkins/safe-chains) reference

User config can override any built-in rule via the configured merge mode.

## Architecture

```
cmd/pgate/                  # CLI entry point
  main.go                   # check / init / hook / version subcommands
  hooks.go                  # Claude Code hook installer

internal/
  verdict/verdict.go        # Core types (Allow / Deny / Ask)
  analyze/analyze.go        # AST-based command extraction
  rules/engine.go           # Rule matching engine
  config/config.go          # TOML config loading and merging
  builtin/
    commands.go             # ~400 hand-curated commands
    generated_commands.go   # ~9,785 auto-generated patterns
    cmd/convert.go          # TOML → Go code generator
```

## License

MIT
