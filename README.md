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
[deny]
flags = { find = ["-exec", "-delete"] }
```

This allows `find . -name '*.go'` but blocks `find . -exec rm {} \;`.

## Installation

### Quick install (recommended)

One-liner — auto-detects your OS and architecture, downloads the latest binary from GitHub Releases:

```bash
curl -sSfL https://raw.githubusercontent.com/happyTonakai/permission-gate/main/install.sh | sh
```

To install a specific version:

```bash
curl -sSfL https://raw.githubusercontent.com/happyTonakai/permission-gate/main/install.sh | VERSION=v1.0.0 sh
```

By default the binary goes to `~/.local/bin/pgate`. Override with `INSTALL_DIR`:

```bash
curl -sSfL https://raw.githubusercontent.com/happyTonakai/permission-gate/main/install.sh | INSTALL_DIR=/usr/local/bin sh
```

Verify:

```bash
pgate version
# permission-gate v1.0.0
```

### Alternative: Build from source

Requires Go 1.25+.

```bash
git clone https://github.com/happytonakai/permission-gate.git
cd permission-gate

# Option A: using just
just install

# Option B: manual build
go build -o pgate ./cmd/pgate
cp pgate ~/.local/bin/    # or anywhere on $PATH

# Option C: go install
go install github.com/happytonakai/permission-gate/cmd/pgate@latest
```

### Install the agent hook

`pgate` ships hooks for three agents. Pick the one(s) you use:

```bash
pgate hook install claude-code   # writes ~/.claude/hooks/permission-gate.sh + registers in ~/.claude/settings.json
pgate hook install opencode      # writes ~/.config/opencode/plugins/permission-gate.ts
pgate hook install pi            # writes ~/.pi/agent/extensions/permission-gate/index.ts
```

Each `install` is safe to re-run — it overwrites the existing hook / plugin / extension file with the latest template (use this to pick up bug fixes in the gate logic). For Claude Code, the `settings.json` registration is de-duplicated and prints "already registered" when nothing changed; for OpenCode and pi, the file is rewritten every time without a "no-op" message.

Uninstall:

```bash
pgate hook uninstall claude-code
pgate hook uninstall opencode
pgate hook uninstall pi
```

After installing, **restart your agent** (Claude Code / OpenCode / pi) so it picks up the new hook / plugin / extension.

## Usage

### Check a command

```bash
pgate check "rm -rf /"
# → deny: denied by pattern "rm"

pgate check "ls -la"
# → allow: allowed by pattern "ls"

pgate check "git push origin main"
# → ask: ask by pattern "git push"
```

### `--json` output

```bash
pgate check --json "echo hello | grep world" | jq
```

```json
{
  "raw_command": "echo hello | grep world",
  "segments": [
    { "command": "echo hello",  "tokens": ["echo","hello"],  "verdict": {"level":0,"reason":"builtin allow: echo","matched":"echo"} },
    { "command": "grep world",  "tokens": ["grep","world"],  "verdict": {"level":0,"reason":"builtin allow: grep","matched":"grep"} }
  ],
  "final": { "level": 0, "reason": "all commands are allowed", "matched": "" }
}
```

`level`: `0` = allow, `1` = deny, `2` = ask. Per-segment verdicts let you see which clause of a pipeline tripped the rule.

### `--detail` output

Same as the default but prints every segment on its own line, with the matched pattern annotated.

### Read command from stdin

When no positional argument is given, `pgate check` reads the command from stdin. This is how the agent extensions invoke it (so multi-line commands and embedded `for/while/if` blocks survive shell-quoting intact):

```bash
echo "rm -rf /" | pgate check
```

### Init config

```bash
pgate init
# Creates ~/.config/permission-gate/config.toml (no-op if it already exists)
```

## Configuration

### File locations

| File                                                | Scope                              |
| --------------------------------------------------- | ---------------------------------- |
| `~/.config/permission-gate/config.toml`             | Global — applies to every project  |
| `<cwd>/.permission-gate.toml`                       | Project — applies only in that dir |

Override with environment variables:

| Variable                          | Overrides                        |
| --------------------------------- | -------------------------------- |
| `PERMISSION_GATE_CONFIG`          | Global config file path          |
| `PERMISSION_GATE_PROJECT_CONFIG`  | Project config file path         |

Both files are re-read on **every** `pgate check` invocation. There is no daemon, no cache, and no reload signal — edit the file and the next bash command the agent runs already uses the new rules. A TOML syntax error fails fast with a clear stderr message rather than silently falling back to the old config.

### Top-level shape

```toml
# .permission-gate.toml (project-level config)
merge_mode = "prepend"   # optional; top-level field. "prepend" (default) | "append" | "overwrite"

[allow]   # auto-approved
[deny]    # auto-blocked
[ask]     # prompt user
```

Each tier takes a `commands` array and a `flags` map. `merge_mode` is a top-level field; it controls how your rules are layered on top of the built-in rules — see [Merge modes](#merge-modes).

`merge_mode` resolution (first non-empty wins):

1. `.permission-gate.toml` (project config) — set per-project
2. `~/.config/permission-gate/config.toml` (global config) — fallback for the whole user account
3. `prepend` — final default

So a global setting applies everywhere unless a project overrides it; a project setting without the field inherits the global value.

### `commands` array

Each entry is either a bare string or an inline table.

**Bare string** — prefix-match against the command's leading tokens:

```toml
[allow]
commands = ["rg", "git log", "kubectl get"]
```

`"git log"` matches `git log --oneline -5` but not `git log-files`. `"rg"` matches `rg -n foo`.

**Inline table** — same prefix match, plus up to four optional refinements:

```toml
[allow]
commands = [
  "rg",
  { cmd = "rm", include_flags = ["-f", "-rf", "-r"], include_args = ["/tmp"] },
]
```

#### Refine fields

All four are optional. A spec matches a command only when **all** of the following hold:

| Field            | Semantic                                                            |
| ---------------- | ------------------------------------------------------------------- |
| `cmd`            | Prefix-match against the command's leading tokens (required).        |
| `include_flags`  | At least one of these flags must appear in the command (any-of).    |
| `exclude_flags`  | None of these flags may appear in the command (none-of).            |
| `include_args`   | Every non-flag arg must start with one of these path prefixes (all-under). |
| `exclude_args`   | No non-flag arg may start with any of these path prefixes (none-prefix). |

**Excludes are checked before includes.** Any exclude hit fails the spec, regardless of what the includes say. All fields are AND-combined.

Short option bundles are expanded when matching flag constraints, but require **all bundled letters to be present** in the command's flag set. So `include_flags = ["-rf"]` matches a command that has both `-r` and `-f` (whether bundled `-rf`, separate `-r -f`, or reordered `-fr`); it does **not** match a command with just `-r` alone. POSIX `--` ends flag scanning; everything after it is a positional argument.

> **Breaking change vs. earlier versions:** older releases used "any letter matches" semantics, so `-rf` matched a command with just `-r`. If you have configs written under that semantic that rely on partial bundles, you'll need to list each flag separately: `include_flags = ["-r", "-f"]`.

##### Examples

```toml
[deny]
commands = [
  # rm only allowed under /tmp and /private/tmp
  { cmd = "rm", include_args = ["/tmp", "/private/tmp"] },

  # git clean blocked at the top of the filesystem or home
  { cmd = "git clean", exclude_args = ["/", "~"] },

  # curl denied when writing to a file (but plain GETs are fine)
  { cmd = "curl", exclude_flags = ["-o", "-O", "--output", "--remote-name"] },

  # kubectl delete only on staging context
  { cmd = "kubectl delete", include_flags = ["--context=staging"] },
]
```

### `flags` map

A `{ command = [flag, ...] }` map. The presence of **any** listed flag (after short-option-bundle expansion) turns the command into the parent tier.

```toml
[deny]
flags = { find = ["-exec", "-delete"], curl = ["--output", "-o"] }
```

This is sugar over an inline table with `include_flags` — use whichever reads better. Built-in flag rules (e.g. `find`'s dangerous flags) live in code; see [Built-in flag deny rules](#built-in-flag-deny-rules).

### Merge modes

Project + global + built-in all stack. `merge_mode` (top-level field, resolution order described in [Top-level shape](#top-level-shape)) decides the order. Within a single file, rules are tried in the order they appear.

| Mode        | Order                                                | Effect                                                                 |
| ----------- | ---------------------------------------------------- | ---------------------------------------------------------------------- |
| `prepend`   | user rules → built-in rules                          | User can override a built-in deny with a user allow (use carefully).   |
| `append`    | built-in rules → user rules                          | Built-in deny wins unless the user has no matching rule at all.        |
| `overwrite` | user rules only                                      | Built-ins are dropped entirely. Useful for curated per-project rulesets. |

In all modes, the **first matching rule wins**, regardless of which tier (allow/deny/ask) it belongs to. Tier order on disk (`[allow]` → `[deny]` → `[ask]`) only matters within a single file's section.

**Concrete example.** Built-in ships `find` allow. In your global config you write:

```toml
# ~/.config/permission-gate/config.toml
merge_mode = "prepend"   # optional; this is the default

[deny]
commands = ["find"]
```

This applies in every project that doesn't override the mode. To make `find` allow again for a specific project, drop a project-level config:

```toml
# ./.permission-gate.toml
merge_mode = "append"    # built-in allow wins over the global deny
```

- `prepend` (default): your deny comes first → `find anything` is denied.
- `append`: built-in allow comes first → `find anything` is allowed (your deny never gets a turn).
- `overwrite`: built-in `find` allow is dropped **along with the global rules** → only this project's rules apply.

### Built-in flag deny rules

The built-in deny flags cover command-execution and deletion vectors. The full list:

| Command  | Flags denied (built-in)                                                                  |
| -------- | ---------------------------------------------------------------------------------------- |
| `find`   | `-exec`, `-execdir`, `-delete`, `-ok`, `-okdir`                                          |
| `sed`    | `-i`, `--in-place`                                                                       |
| `tar`    | `--to-command`, `-I`, `--use-compress-program`, `--checkpoint-action`                    |
| `curl`   | `--output`, `-o`, `--remote-name`, `-O`, `--upload-file`, `-T`                           |
| `wget`   | `-O`, `--output-document`, `-o`, `--output-file`                                        |
| `dd`     | `if=`, `of=`                                                                             |
| `docker` | `exec`, `-it`, `--interactive`, `--tty`                                                   |
| `kill`   | `-9`, `--signal`                                                                         |
| `python` | `-c`                                                                                     |
| `chmod`  | `-R`, `--recursive`                                                                      |
| `chown`  | `-R`, `--recursive`                                                                      |

Pure-output flags (`-print`, `-printf`, `-fls`, `-fprint`, `-fprintf` for `find`) are intentionally **not** in the deny list — they cannot execute commands or delete files.

### Complete examples

**1. Minimal safe setup** — override one built-in and deny a few extras:

```toml
# ~/.config/permission-gate/config.toml

[allow]
commands = ["rg", "fd", "bat", "delta", "lazygit"]

[deny]
commands = ["sudo", "shutdown", "reboot", "halt"]
```

**2. Multi-project with per-project rules** — global stays small, projects add their own:

```toml
# ~/.config/permission-gate/config.toml (global)
[allow]
commands = ["rg", "fd"]
```

```toml
# /path/to/my-project/.permission-gate.toml
[ask]
commands = ["terraform apply", "kubectl apply", "ansible-playbook"]

[deny]
commands = [
  # rm limited to ./build
  { cmd = "rm", include_args = ["./build", "./dist"] },
]
```

**3. Team template (overwrite mode, locked-down)** — curated ruleset, both built-ins and global rules dropped per-project:

```toml
# ~/.config/permission-gate/config.toml (shared via dotfiles repo)
[allow]
commands = ["ls", "cat", "grep", "rg", "git log", "git status", "git diff", "go test"]

[deny]
commands = [
  "rm", "sudo", "shutdown",
  { cmd = "git", exclude_args = ["./"] },        # no git writes outside repo
  { cmd = "kubectl", include_flags = ["--context=prod"] },  # prod ctx always blocked
]
flags = { find = ["-exec", "-delete", "-ok"] }

[ask]
commands = ["git push", "git commit", "go mod tidy"]
```

```toml
# Drop this in every project's cwd (or symlink it into a shared location)
# to enforce overwrite mode for that project — it then ignores BOTH the
# built-in rules AND the global config above, using only the project file.
merge_mode = "overwrite"
```

## Architecture

```
cmd/pgate/                  # CLI entry point
  main.go                   # check / init / hook / version subcommands
  hooks.go                  # Claude Code / OpenCode / pi hook installer

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

## Built-in commands

Permission Gate ships with ~10,000 built-in allow patterns covering:

- File operations: `ls`, `cat`, `echo`, `find`, `grep`, `head`, `tail`
- Version control: `git log`, `git status`, `git diff` (read-only), `git push` (ask)
- Development: `go build`, `npm install`, `pip`, `cargo`, `docker ps`
- System: `uname`, `df`, `du`, `ps`, `uptime`
- And many more — generated from the [safe-chains](https://github.com/michaeldhopkins/safe-chains) reference

User config can override any built-in rule via the configured merge mode.

## License

MIT
