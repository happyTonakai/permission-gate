package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func installHook(target string) error {
	binary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine binary path: %w", err)
	}
	binary, _ = filepath.Abs(binary)

	switch target {
	case "claude-code":
		return installClaudeCodeHook(binary)
	case "opencode":
		return installOpenCodeHook(binary)
	case "pi-agent":
		return installPiAgentHook(binary)
	default:
		return fmt.Errorf("unknown target: %s (supported: claude-code, opencode, pi-agent)", target)
	}
}

func uninstallHook(target string) error {
	switch target {
	case "claude-code":
		return removeClaudeCodeHook()
	case "opencode":
		return removeOpenCodeHook()
	case "pi-agent":
		return removePiAgentHook()
	default:
		return fmt.Errorf("unknown target: %s (supported: claude-code, opencode, pi-agent)", target)
	}
}

// ─── Claude Code ────────────────────────────────────────────────

const claudeHookScript = `#!/usr/bin/env bash
# Permission Gate — Claude Code pre-tool hook
# Installed by pgate hook install claude-code

eval "$(permission-gate hook-env 2>/dev/null)" 2>/dev/null || true
`

func claudeHookDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude", "hooks"), nil
}

func installClaudeCodeHook(binary string) error {
	// We install as a PermissionRequest hook — a script that pgate runs.
	hookDir, err := claudeHookDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(hookDir, 0755); err != nil {
		return err
	}

	hookPath := filepath.Join(hookDir, "permission-gate.sh")
	content := fmt.Sprintf(`#!/usr/bin/env bash
# Permission Gate — Claude Code PermissionRequest hook
# Installed by: pgate hook install claude-code

exec %s hook claude-request
`, binary)

	if err := os.WriteFile(hookPath, []byte(content), 0755); err != nil {
		return err
	}
	return nil
}

func removeClaudeCodeHook() error {
	hookDir, err := claudeHookDir()
	if err != nil {
		return err
	}
	hookPath := filepath.Join(hookDir, "permission-gate.sh")
	if err := os.Remove(hookPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ─── OpenCode ───────────────────────────────────────────────────

func installOpenCodeHook(binary string) error {
	content := fmt.Sprintf(`import type { ExtensionAPI } from "@opencode/plugin-api";

export default function (api: ExtensionAPI) {
  api.on("tool:bash", async (event, ctx) => {
    const cmd = event.input.command;
    const proc = Bun.spawn(["%s", "check", "--json"], {
      stdin: new TextEncoder().encode(cmd),
    });
    const out = await new Response(proc.stdout).text();
    const result = JSON.parse(out);
    if (result.final.level === "deny") {
      return { block: true, reason: result.final.reason || "Blocked by permission gate" };
    }
    if (result.final.level === "ask") {
      const ok = await ctx.ui.confirm("Run this command?", cmd);
      if (!ok) return { block: true, reason: "Cancelled by user" };
    }
  });
}
`, binary)
	_ = content
	return fmt.Errorf("OpenCode hook not yet implemented")
}

func removeOpenCodeHook() error {
	return fmt.Errorf("OpenCode hook not yet implemented")
}

// ─── Pi Agent ────────────────────────────────────────────────────

const piHookDir = ".pi/agent/extensions/permission-gate"

func installPiAgentHook(binary string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, piHookDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Pi agent extensions are TypeScript — generate a small wrapper
	content := fmt.Sprintf(`// Permission Gate — Pi Agent extension
// Installed by: pgate hook install pi-agent

import { execSync } from "node:child_process";

export default function (pi) {
  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName !== "bash") return;
    const cmd = event.input.command;
    try {
      const out = execSync("%s check --json " + JSON.stringify(cmd), { encoding: "utf-8" });
      const result = JSON.parse(out);
      if (result.final.level === "deny") {
        if (ctx.hasUI) {
          const ok = await ctx.ui.confirm("Command is denied by permission gate", cmd);
          if (!ok) return { block: true, reason: "Blocked by permission gate" };
        }
        return { block: true, reason: "Blocked by permission gate" };
      }
      if (result.final.level === "ask") {
        if (ctx.hasUI) {
          const ok = await ctx.ui.confirm("Command needs confirmation", cmd);
          if (!ok) return { block: true, reason: "Cancelled by user" };
        }
        return;
      }
    } catch (e) {
      // fallthrough on error
    }
  });
}
`, binary)
	if err := os.WriteFile(filepath.Join(dir, "index.ts"), []byte(content), 0644); err != nil {
		return err
	}
	return nil
}

func removePiAgentHook() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, piHookDir)
	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Ensure the binary is in PATH for hook contexts
func ensureInPATH(binary string) error {
	// Symlink into ~/.local/bin/ if not already in PATH
	home, _ := os.UserHomeDir()
	localBin := filepath.Join(home, ".local", "bin")
	target := filepath.Join(localBin, "permission-gate")

	if _, err := os.Stat(target); os.IsNotExist(err) {
		if err := os.MkdirAll(localBin, 0755); err != nil {
			return err
		}
		return os.Symlink(binary, target)
	}
	return nil
}

// isInteractive returns true if stdin is a terminal (user is running directly)
func isInteractive() bool {
	stat, _ := os.Stdin.Stat()
	return (stat.Mode() & os.ModeCharDevice) != 0
}

// runPgateCheck calls pgate check --json and returns the result.
func runPgateCheck(cmd string) (string, error) {
	binary, err := os.Executable()
	if err != nil {
		return "", err
	}
	out, err := exec.Command(binary, "check", "--json", cmd).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
