# AGENTS.md

This file provides guidance to coding agents when working with code in this repository.

## Build & test

- Use `just` for common tasks: `just build`, `just test`, `just lint`, `just fmt`, `just check` (runs fmt + test + build), `just test-verbose`, `just test-race`.
- `just lint` uses `staticcheck ./...`. `go vet ./...` is also run in CI but not in `just lint` — run it separately before committing.
- Format with `go fmt ./...` (also `just fmt`).
- Standard `go test ./...` works, but prefer `just test` to stay consistent.
- CI runs on pushes/PRs to `main` only.

## Code conventions

- This is a single Go module at `github.com/happyTonakai/permission-gate`, Go 1.25.
- Built on `mvdan.cc/sh/v3` for shell AST parsing and `pelletier/go-toml/v2` for config.
- `cmd/pgate/` is the CLI entry point; `internal/` packages are not importable outside the module.
- The `cmd/batch-compare/` command is a utility, not part of the main binary.
- Architecture: CLI → AST extraction (`internal/analyze`) → rule matching (`internal/rules`) → verdict (`internal/verdict`), with TOML config loaded by `internal/config`. Built-in rules live in `internal/builtin/`.

## Agent hooks

- `pgate hook install pi` writes the permission gate extension to `~/.pi/agent/extensions/permission-gate/`. After installing, restart the agent.
- If `pgate` is not on `$PATH`, the pi extension silently disables itself (the extension catches the error and returns without blocking). Build and install first with `just install && pgate hook install pi`.

## Communication

- When refactoring or making design decisions, explain tradeoffs and show alternatives.
