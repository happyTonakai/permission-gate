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
	case "claude":
		return installClaudeHook(binary)
	case "opencode":
		return installOpenCodeHook(binary)
	case "pi":
		return installPiAgentHook(binary)
	default:
		return fmt.Errorf("unknown target: %s (supported: claude, opencode, pi)", target)
	}
}

func uninstallHook(target string) error {
	switch target {
	case "claude":
		return removeClaudeHook()
	case "opencode":
		return removeOpenCodeHook()
	case "pi":
		return removePiAgentHook()
	default:
		return fmt.Errorf("unknown target: %s (supported: claude, opencode, pi)", target)
	}
}

// ─── Claude ──────────────────────────────────────────────────────
//
// Claude hook system: shell scripts registered in settings.json
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

func installClaudeHook(binary string) error {
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
# Installed by: pgate hook install claude
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

func removeClaudeHook() error {
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

function localTS() {
  const d = new Date(), tzo = -d.getTimezoneOffset()
  const pad = (n:number) => String(n).padStart(2, '0')
  return d.getFullYear() + '-' + pad(d.getMonth()+1) + '-' + pad(d.getDate()) + 'T' +
    pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()) +
    (tzo >= 0 ? '+' : '-') + pad(Math.floor(tzo/60)) + ':' + pad(tzo%60)
}

function log(level: string, command: string, reason?: string) {
  try {
    if (!existsSync(LOG_DIR)) mkdirSync(LOG_DIR, { recursive: true })
    const date = new Date().toISOString().slice(0, 10)
    const file = join(LOG_DIR, "permission-gate-" + date + ".log")
    const entry = JSON.stringify({ ts: localTS(), level, command, reason }) + "\n"
    appendFileSync(file, entry, "utf-8")
    cleanupOldLogs(7)
  } catch { /* silent */ }
}

const MS_PER_DAY = 24 * 60 * 60 * 1000
const bt = String.fromCharCode(96)

function cleanupOldLogs(keepDays: number) {
  try {
    if (!existsSync(LOG_DIR)) return
    const cutoff = Date.now() - keepDays * MS_PER_DAY
    for (const name of readdirSync(LOG_DIR)) {
      if (!name.startsWith("permission-gate-")) continue
      const datePart = name.slice(16, 26) // "permission-gate-YYYY-MM-DD.log" → "YYYY-MM-DD"
      const t = Date.parse(datePart)
      if (Number.isFinite(t) && t < cutoff) {
        unlinkSync(join(LOG_DIR, name))
      }
    }
  } catch { /* silent */ }
}

export const PermissionGatePlugin: Plugin = async ({ $ }) => {
  let denialCount = 0

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
        // Pass the raw multi-line command via stdin. Embedding it as a
        // shell argument breaks on newlines: bash inside double quotes
        // treats \n as two literal characters, not a real newline, so
        // pgate receives a single line and mvdan/sh fails to parse
        // constructs like "for x in y; do" followed by an indented body.
        // pgate's check subcommand reads the command from stdin when
        // no positional arg is given.
        const proc = $` + bt + `pgate check --json` + bt + `.quiet().nothrow()
        const w = proc.stdin.getWriter()
        await w.write(new TextEncoder().encode(command))
        await w.close()
        const result = await proc
        const parsed = JSON.parse(String(result.stdout).trim())
        const lvl = parsed.final?.level

        if (lvl === 1) {
          const ruleReason = parsed.final?.reason ?? "denied"
          denialCount++
          let msg: string
          if (denialCount === 1) {
            msg = bt + "\nPermission Gate denied this command: " + ruleReason + "\n\nThis operation is classified as dangerous. The following two guidelines apply:\n\n1. If the user's **goal** can be accomplished by a fundamentally different, safer approach (e.g. reading logs instead of opening a shell), use that safer approach. This is finding a better way to achieve the intent.\n\n2. Do NOT attempt to rephrase, reword, or otherwise rewrite this same command in a different form to bypass the check. Switching docker exec -it container bash to docker exec -it container sh or using nsenter to get the same shell access is still performing the same dangerous operation — that is bypassing, not a safer alternative.\n\nIf the user's instruction truly requires this exact command and there is no fundamentally safer alternative, you must stop and explicitly ask the user to grant the required permission — do not try to work around the gate." + bt
          } else {
            msg = bt + "\nPermission Gate denied this command: " + ruleReason + "\n\nRemember the guidelines: do not attempt to bypass and seek safer alternatives if possible. If neither works, you must ask the user for permission." + bt
          }
          log("deny", command, "count=" + denialCount + " reason=" + ruleReason)
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

function localTS() {
  const d = new Date(), tzo = -d.getTimezoneOffset();
  const pad = (n: number) => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + pad(d.getMonth()+1) + '-' + pad(d.getDate()) + 'T' +
    pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()) +
    (tzo >= 0 ? '+' : '-') + pad(Math.floor(tzo/60)) + ':' + pad(tzo%60);
}

function log(level: string, command: string, reason?: string) {
  try {
    if (!existsSync(LOG_DIR)) mkdirSync(LOG_DIR, { recursive: true });
    const date = new Date().toISOString().slice(0, 10);
    const file = join(LOG_DIR, "permission-gate-" + date + ".log");
    const entry = JSON.stringify({ ts: localTS(), level, command, reason }) + "\n";
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
      const datePart = name.slice(16, 26);
      const t = Date.parse(datePart);
      if (Number.isFinite(t) && t < cutoff) {
        unlinkSync(join(LOG_DIR, name));
      }
    }
  } catch { /* silent */ }
}

export default function (pi: any) {
  let denialCount = 0;

  pi.on("tool_call", async (event: any, ctx: any) => {
    if (event.toolName !== "bash") return;

    const command = event.input.command as string;
    if (!command) return;

    try {
      // Pass the raw multi-line command via stdin. Encoding the command
      // into a shell argument (e.g. via JSON.stringify) breaks on newlines:
      // bash inside double quotes treats \n as two literal characters, not
      // a real newline, so pgate receives a single line and mvdan/sh fails
      // to parse constructs like "for x in y; do" followed by an indented
      // body. pgate's check subcommand already reads the command from
      // stdin when no positional arg is given.
      const out = execSync("pgate check --json", {
        encoding: "utf-8",
        input: command,
      });
      const result = JSON.parse(out);
      const lvl = result.final?.level;

      if (lvl === 1) {
        // Deny means deny — block immediately, no popup. Showing a confirm
        // dialog here would make Deny indistinguishable from Ask, and a
        // "user override" path would let denied commands run anyway.
        const ruleReason = result.final?.reason ?? "denied";
        denialCount++;
        let reason: string;
        if (denialCount === 1) {
          reason = bt + "\nPermission Gate denied this command: " + ruleReason + "\n\nThis operation is classified as dangerous. The following two guidelines apply:\n\n1. If the user's **goal** can be accomplished by a fundamentally different, safer approach (e.g. reading logs instead of opening a shell), use that safer approach. This is finding a better way to achieve the intent.\n\n2. Do NOT attempt to rephrase, reword, or otherwise rewrite this same command in a different form to bypass the check. Switching docker exec -it container bash to docker exec -it container sh or using nsenter to get the same shell access is still performing the same dangerous operation — that is bypassing, not a safer alternative.\n\nIf the user's instruction truly requires this exact command and there is no fundamentally safer alternative, you must stop and explicitly ask the user to grant the required permission — do not try to work around the gate." + bt;
        } else {
          reason = bt + "\nPermission Gate denied this command: " + ruleReason + "\n\nRemember the guidelines: do not attempt to bypass and seek safer alternatives if possible. If neither works, you must ask the user for permission." + bt;
        }
        log("deny", command, "count=" + denialCount + " reason=" + ruleReason);
        return { block: true, reason };
      }

      if (lvl === 2) {
        log("ask", command);
        if (ctx.hasUI) {
          const ok = await ctx.ui.confirm(
            "Command needs confirmation",
            command,
          );
          if (!ok) return { block: true, reason: "Cancelled by user" };
          return; // user approved → pass through
        }
        return; // no UI → pass through, let Pi's default flow handle it
      }

      log("allow", command);
    } catch {
      // fallthrough on error
    }
  });
}
`

// Pi auto-discovers both layouts from ~/.pi/agent/extensions/:
//
//	*.ts             — single-file extension (we use this)
//	*/index.ts       — directory form (older layout; cleaned up on install/uninstall)
const piHookDir = ".pi/agent/extensions"
const piHookFile = "permission-gate.ts"
const piHookLegacyDir = "permission-gate" // older layout: extensions/permission-gate/index.ts

func installPiAgentHook(binary string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, piHookDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	removeLegacyPiAgentHook(home)

	hookPath := filepath.Join(dir, piHookFile)
	if err := os.WriteFile(hookPath, []byte(piAgentExtension), 0644); err != nil {
		return err
	}
	fmt.Println("Extension written to", hookPath)
	return nil
}

func removePiAgentHook() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	hookPath := filepath.Join(home, piHookDir, piHookFile)
	if err := os.Remove(hookPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	removeLegacyPiAgentHook(home)
	fmt.Println("Removed Pi Agent extension")
	return nil
}

// removeLegacyPiAgentHook best-effort removes the older directory-form
// extension at ~/.pi/agent/extensions/permission-gate/. If present it
// would be auto-discovered by pi alongside the new single-file extension,
// causing the gate to run twice. Errors are reported to stderr but do
// not abort the caller.
func removeLegacyPiAgentHook(home string) {
	legacy := filepath.Join(home, piHookDir, piHookLegacyDir)
	if _, err := os.Stat(legacy); err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Warning: could not stat legacy extension directory %s: %v\n", legacy, err)
		}
		return
	}
	if err := os.RemoveAll(legacy); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not remove legacy extension directory %s: %v\n", legacy, err)
		return
	}
	fmt.Println("Removed legacy extension directory:", legacy)
}
