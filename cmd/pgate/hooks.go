package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	case "pi":
		return installPiAgentHook(binary)
	default:
		return fmt.Errorf("unknown target: %s (supported: claude-code, opencode, pi)", target)
	}
}

func uninstallHook(target string) error {
	switch target {
	case "claude-code":
		return removeClaudeCodeHook()
	case "opencode":
		return removeOpenCodeHook()
	case "pi":
		return removePiAgentHook()
	default:
		return fmt.Errorf("unknown target: %s (supported: claude-code, opencode, pi)", target)
	}
}

// ─── Claude Code ────────────────────────────────────────────────
//
// Claude Code hook system: shell scripts registered in settings.json
// under hooks.PermissionRequest. Each receives JSON on stdin:
//
//	{"tool_name":"Bash","tool_input":{"command":"..."},"cwd":"...","transcript_path":"..."}
//
// Must print to stdout:
//
//	{"hookSpecificOutput":{"hookEventName":"PermissionRequest",
//	  "decision":{"behavior":"allow"|"deny"|"ask","message":"..."}}}

func claudeHookDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude", "hooks"), nil
}

func installClaudeCodeHook(binary string) error {
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
	fmt.Println("Hook script written to", hookPath)

	if err := registerClaudeHook(hookPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not auto-register in settings.json: %v\n", err)
		fmt.Fprintln(os.Stderr, "To register manually, add to ~/.claude/settings.json:")
		fmt.Fprintln(os.Stderr, `  "PermissionRequest": [{"hooks": [{"command": "`+hookPath+`", "type": "command"}], "matcher": "Bash"}]`)
	}
	return nil
}

type claudeSettings struct {
	Hooks map[string][]claudeHookGroup `json:"hooks"`
}

type claudeHookGroup struct {
	Hooks   []claudeHookEntry `json:"hooks"`
	Matcher string            `json:"matcher"`
}

type claudeHookEntry struct {
	Command string `json:"command"`
	Type    string `json:"type"`
}

func registerClaudeHook(hookPath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	settingsPath := filepath.Join(home, ".claude", "settings.json")

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", settingsPath, err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse %s: %w", settingsPath, err)
	}

	// Build a hook entry map (using map[string]interface{} to preserve all fields)
	hookEntry := map[string]interface{}{
		"command": hookPath,
		"type":    "command",
	}
	permEntry := map[string]interface{}{
		"hooks":   []interface{}{hookEntry},
		"matcher": "Bash",
	}

	// Ensure hooks map exists
	hooks, _ := raw["hooks"].(map[string]interface{})
	if hooks == nil {
		hooks = make(map[string]interface{})
		raw["hooks"] = hooks
	}

	// Ensure PermissionRequest list exists
	permList, _ := hooks["PermissionRequest"].([]interface{})

	// Check if already registered (by command path)
	already := false
	for _, entry := range permList {
		e, _ := entry.(map[string]interface{})
		if e == nil {
			continue
		}
		hooksList, _ := e["hooks"].([]interface{})
		for _, h := range hooksList {
			he, _ := h.(map[string]interface{})
			if he == nil {
				continue
			}
			if cmd, _ := he["command"].(string); cmd == hookPath {
				already = true
			}
		}
	}

	if !already {
		permList = append(permList, permEntry)
		hooks["PermissionRequest"] = permList
	}

	// Write back with backup
	updated, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	updated = append(updated, '\n')

	backupPath := settingsPath + ".bak"
	os.WriteFile(backupPath, data, 0644) // best-effort backup

	if err := os.WriteFile(settingsPath, updated, 0644); err != nil {
		os.WriteFile(settingsPath, data, 0644) // restore on failure
		return fmt.Errorf("write %s: %w", settingsPath, err)
	}

	if already {
		fmt.Println("Hook already registered in ~/.claude/settings.json")
	} else {
		fmt.Println("Registered in ~/.claude/settings.json")
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
	fmt.Println("Removed hook script")
	return nil
}

// ─── OpenCode ───────────────────────────────────────────────────
//
// OpenCode plugins: TypeScript files in ~/.config/opencode/plugins/,
// auto-discovered. Each exports a Plugin function that hooks into
// "tool.execute.before" to intercept bash commands.

// backtick helper for TypeScript template literals in Go strings
var bt = string(rune(96)) // `

var openCodePlugin = `import type { Plugin } from "@opencode-ai/plugin"
import { appendFileSync, mkdirSync, existsSync, readdirSync, unlinkSync } from "node:fs"
import { join } from "node:path"
import { homedir } from "node:os"

const LOG_DIR = join(homedir(), ".config", "opencode", "logs")

function log(level: string, command: string, reason?: string) {
  try {
    if (!existsSync(LOG_DIR)) mkdirSync(LOG_DIR, { recursive: true })
    const date = new Date().toISOString().slice(0, 10)
    const file = join(LOG_DIR, "permission-gate-" + date + ".log")
    const entry = JSON.stringify({ ts: new Date().toISOString(), level, command, reason }) + "\n"
    appendFileSync(file, entry, "utf-8")
    cleanupOldLogs(7)
  } catch { /* silent */ }
}

const MS_PER_DAY = 24 * 60 * 60 * 1000

function cleanupOldLogs(keepDays: number) {
  try {
    if (!existsSync(LOG_DIR)) return
    const cutoff = Date.now() - keepDays * MS_PER_DAY
    for (const name of readdirSync(LOG_DIR)) {
      if (!name.startsWith("permission-gate-")) continue
      const datePart = name.slice(17, 27) // "permission-gate-YYYY-MM-DD.log" → "YYYY-MM-DD"
      const t = Date.parse(datePart)
      if (Number.isFinite(t) && t < cutoff) {
        unlinkSync(join(LOG_DIR, name))
      }
    }
  } catch { /* silent */ }
}

export const PermissionGatePlugin: Plugin = async ({ $ }) => {
  try {
    await $` + bt + `which pgate` + bt + `.quiet()
  } catch {
    console.warn("[pgate] pgate binary not found in PATH — plugin disabled")
    return {}
  }

  return {
    "tool.execute.before": async (input) => {
      const tool = String(input?.tool ?? "").toLowerCase()
      if (tool !== "bash" && tool !== "shell") return

      const args = input?.args
      if (!args || typeof args !== "object") return
      const command = (args as Record<string, unknown>).command
      if (typeof command !== "string" || !command) return

      try {
        const result = await $` + bt + `pgate check --json ${command}` + bt + `.quiet().nothrow()
        const parsed = JSON.parse(String(result.stdout).trim())
        const lvl = parsed.final?.Level ?? parsed.final?.level

        if (lvl === 1) {
          const msg = "Permission Gate: " + (parsed.final?.reason ?? "denied")
          log("deny", command, msg)
          return { block: true, reason: msg }
        }
        if (lvl === 2) {
          log("ask", command)
          return  // let OpenCode's default permission flow handle it
        }
        log("allow", command)
      } catch {
        // fallthrough
      }
    },
  }
}
`

func installOpenCodeHook(binary string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	pluginDir := filepath.Join(home, ".config", "opencode", "plugins")
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		return err
	}

	pluginPath := filepath.Join(pluginDir, "permission-gate.ts")
	if err := os.WriteFile(pluginPath, []byte(openCodePlugin), 0644); err != nil {
		return err
	}
	fmt.Println("Plugin written to", pluginPath)
	return nil
}

func removeOpenCodeHook() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	pluginPath := filepath.Join(home, ".config", "opencode", "plugins", "permission-gate.ts")
	if err := os.Remove(pluginPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Println("Removed OpenCode plugin")
	return nil
}

// ─── Pi Agent ───────────────────────────────────────────────────
//
// Pi Agent extensions: TypeScript files in ~/.pi/agent/extensions/,
// auto-discovered. Each exports a default function (pi) that hooks
// into "tool_call" to intercept bash commands.

const piAgentExtension = `// Permission Gate — Pi extension
// Installed by: pgate hook install pi

import { execSync } from "node:child_process";
import { appendFileSync, mkdirSync, existsSync, readdirSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const LOG_DIR = join(homedir(), ".pi", "agent", "logs");
const MS_PER_DAY = 24 * 60 * 60 * 1000;

function log(level: string, command: string, reason?: string) {
  try {
    if (!existsSync(LOG_DIR)) mkdirSync(LOG_DIR, { recursive: true });
    const date = new Date().toISOString().slice(0, 10);
    const file = join(LOG_DIR, "permission-gate-" + date + ".log");
    const entry = JSON.stringify({ ts: new Date().toISOString(), level, command, reason }) + "\n";
    appendFileSync(file, entry, "utf-8");
    cleanupOldLogs(7);
  } catch { /* silent */ }
}

function cleanupOldLogs(keepDays: number) {
  try {
    if (!existsSync(LOG_DIR)) return;
    const cutoff = Date.now() - keepDays * MS_PER_DAY;
    for (const name of readdirSync(LOG_DIR)) {
      if (!name.startsWith("permission-gate-")) continue;
      const datePart = name.slice(17, 27);
      const t = Date.parse(datePart);
      if (Number.isFinite(t) && t < cutoff) {
        unlinkSync(join(LOG_DIR, name));
      }
    }
  } catch { /* silent */ }
}

export default function (pi: any) {
  pi.on("tool_call", async (event: any, ctx: any) => {
    if (event.toolName !== "bash") return;

    const command = event.input.command as string;
    if (!command) return;

    try {
      const out = execSync("pgate check --json " + JSON.stringify(command), {
        encoding: "utf-8",
      });
      const result = JSON.parse(out);
      const lvl = result.final?.Level ?? result.final?.level;

      if (lvl === 1) {
        log("deny", command, result.final?.reason);
        if (ctx.hasUI) {
          const ok = await ctx.ui.confirm(
            "Command denied by Permission Gate",
            command,
          );
          if (!ok) return { block: true, reason: "Blocked by Permission Gate" };
        }
        return { block: true, reason: "Blocked by Permission Gate" };
      }

      if (lvl === 2) {
        log("ask", command);
        if (ctx.hasUI) {
          const ok = await ctx.ui.confirm(
            "Command needs confirmation",
            command,
          );
          if (!ok) return { block: true, reason: "Cancelled by user" };
        }
        return;
      }

      log("allow", command);
    } catch {
      // fallthrough on error
    }
  });
}
`

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

	indexPath := filepath.Join(dir, "index.ts")
	if err := os.WriteFile(indexPath, []byte(piAgentExtension), 0644); err != nil {
		return err
	}
	fmt.Println("Extension written to", indexPath)
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
	fmt.Println("Removed Pi Agent extension")
	return nil
}
