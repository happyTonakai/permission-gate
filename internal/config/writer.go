package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Scope selects which config file the writer targets.
//
// User    → globalConfigPath()  (PERMISSION_GATE_CONFIG or ~/.config/permission-gate/config.toml)
// Project → projectConfigPath(cwd)  (PERMISSION_GATE_PROJECT_CONFIG or <cwd>/.permission-gate.toml)
//
// The two paths are exactly what ResolveConfig reads from, so writing
// to a scope is guaranteed to influence the next pgate check in that
// scope.
type Scope string

const (
	ScopeUser    Scope = "user"
	ScopeProject Scope = "project"
)

// ParseScope normalizes an empty/invalid scope into a useful error.
// Empty input is treated as ScopeUser because that is the CLI default;
// anything non-empty must be one of the two documented values.
func ParseScope(s string) (Scope, error) {
	switch Scope(s) {
	case "":
		return ScopeUser, nil
	case ScopeUser, ScopeProject:
		return Scope(s), nil
	default:
		return "", fmt.Errorf("invalid scope %q (want user|project)", s)
	}
}

// AddAllowCommand appends spec to the [allow].commands list of the chosen
// scope's config file. On success it returns:
//
//	path    — absolute path of the file actually written (or already present)
//	added   — true if spec is now in the file; false if it was already present
//	err     — any I/O / parse error encountered
//
// Design: text-level surgical edit (no marshal/unmarshal round-trip).
// We splice the new entry directly into the existing bytes so that
// comments, blank lines, formatting, and even top-level keys placed
// AFTER a [table] header (a known go-toml/v2 quirk) survive intact.
//
// Behavior matrix:
//
//   - Missing file                  → create a minimal one (just the entry)
//   - File exists, no [allow]       → append `[allow]\ncommands = ["spec"]`
//   - File exists, [allow] no cmds  → insert `commands = ["spec"]` after [allow]
//   - commands = []                 → replace with `commands = ["spec"]`
//   - commands = ["a","b"] 1-line   → `commands = ["a","b","spec"]`
//   - commands = [ multi-line ]     → insert spec on a new line; respect trailing comma
//   - bare-string match already     → dedup, file unchanged
//
// Inline tables in commands are passed over by a small bracket/string
// scanner — see arrayScanner. Strings are TOML-escaped via tomlEncodeString.
func AddAllowCommand(spec string, scope Scope) (path string, added bool, err error) {
	target, err := resolveScopePath(scope)
	if err != nil {
		return "", false, err
	}

	// Branch 1: missing file → create minimal config with just the entry.
	raw, readErr := os.ReadFile(target)
	if readErr != nil && !os.IsNotExist(readErr) {
		return "", false, fmt.Errorf("read %s: %w", target, readErr)
	}
	if os.IsNotExist(readErr) {
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return "", false, fmt.Errorf("mkdir %s: %w", filepath.Dir(target), err)
		}
		content := buildMinimalConfig(spec)
		if err := os.WriteFile(target, content, 0644); err != nil {
			return "", false, fmt.Errorf("write %s: %w", target, err)
		}
		return target, true, nil
	}

	// Branch 2: existing file → surgical edit.
	out, dedup, err := spliceAllowCommand(raw, spec)
	if err != nil {
		return "", false, fmt.Errorf("edit %s: %w", target, err)
	}
	if dedup {
		return target, false, nil
	}
	if err := os.WriteFile(target, out, 0644); err != nil {
		return "", false, fmt.Errorf("write %s: %w", target, err)
	}
	return target, true, nil
}

// resolveScopePath maps a Scope to the on-disk path of the file that
// AddAllowCommand will read & write. centralizes the env / home / cwd
// resolution so both the user and project branches can be unit-tested.
func resolveScopePath(scope Scope) (string, error) {
	switch scope {
	case ScopeUser:
		return globalConfigPath(), nil
	case ScopeProject:
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("get cwd: %w", err)
		}
		return projectConfigPath(cwd), nil
	default:
		return "", fmt.Errorf("invalid scope %q", scope)
	}
}

// buildMinimalConfig emits a brand-new config file containing only the
// just-added spec. Kept deliberately minimal — no [deny] / [ask] sections,
// no comments — so the file the user sees matches exactly what they did
// (one allow entry). Future `pgate add` calls will hit spliceAllowCommand
// instead and start preserving whatever is there.
func buildMinimalConfig(spec string) []byte {
	var b bytes.Buffer
	b.WriteString("[allow]\ncommands = [")
	b.WriteString(tomlEncodeString(spec))
	b.WriteString("]\n")
	return b.Bytes()
}

// spliceAllowCommand performs the text-level surgical edit on an existing
// file's bytes. Returns the new bytes plus a dedup flag (true means caller
// should NOT write back, the content is unchanged).
//
// All complexity lives here:
//
//  1. Find the [allow] section's header. (findAllowSection returns only
//     the start offset; section-boundary detection is delegated to
//     findCommandsLine, which handles multi-line `commands =\n[…]`.)
//
//  2. Within [allow], find the `commands =` line, then the `[...]` array's
//     matching `]` (arrayScanner handles nested arrays, strings, comments,
//     inline tables).
//
//  3. Decide insertion strategy based on what's there:
//     - no [allow]: caller has already handled this (create new file)
//     - [allow] but no commands line: insert one right after [allow]
//     - commands = []: replace contents
//     - single-line non-empty: insert `, "spec"` before `]`
//     - multi-line: insert on a new line, adding `,` if last entry lacks it
//
//  4. Dedup check: before any edit, scan the array for an exact bare-string
//     match of spec. If found, return dedup=true with content unchanged.
func spliceAllowCommand(content []byte, spec string) ([]byte, bool, error) {
	secStart, hasAllow := findAllowSection(content)
	if !hasAllow {
		// No [allow] section. Append a new one at EOF, preserving a
		// trailing newline if the original ended with one.
		var out bytes.Buffer
		out.Write(content)
		if len(content) == 0 || content[len(content)-1] != '\n' {
			out.WriteByte('\n')
		}
		// Blank line separator if the existing content has anything after
		// the last newline (i.e., the last "line" isn't empty).
		if len(bytes.TrimSpace(content)) > 0 {
			out.WriteByte('\n')
		}
		out.WriteString("[allow]\ncommands = [")
		out.WriteString(tomlEncodeString(spec))
		out.WriteString("]\n")
		return out.Bytes(), false, nil
	}

	// Within [allow], find the `commands =` line. Skip past the header
	// line first so the `[allow]` token itself doesn't trip the
	// "we left this section" check below.
	bodyStart := lineEnd(content, secStart)
	cmdsStart, hasCmds := findCommandsLine(content, bodyStart, len(content))

	if !hasCmds {
		// Insert a new commands line right after the [allow] header.
		insertAt := bodyStart
		var b bytes.Buffer
		b.Write(content[:insertAt])
		b.WriteString("commands = [")
		b.WriteString(tomlEncodeString(spec))
		b.WriteString("]\n")
		b.Write(content[insertAt:])
		return b.Bytes(), false, nil
	}

	// Find the array `[...]` bounds.
	arrOpen, arrClose, ok := findCommandsArray(content, cmdsStart, len(content))
	if !ok {
		return nil, false, fmt.Errorf("could not locate [allow].commands array")
	}

	// Dedup: scan for exact bare-string match within the array.
	if containsBareString(content, arrOpen+1, arrClose, spec) {
		return content, true, nil
	}

	// Build the insertion.
	inner := content[arrOpen+1 : arrClose]
	insertAt, insertion := buildInsertion(inner, arrOpen, arrClose, spec)

	// Splice at insertAt. For the multi-line case, insertAt sits just
	// after the last entry's terminator, so the trailing whitespace and
	// closing `]` survive intact — no spurious blank line.
	var out bytes.Buffer
	out.Write(content[:insertAt])
	out.Write(insertion)
	out.Write(content[insertAt:])
	return out.Bytes(), false, nil
}

// findAllowSection locates the [allow] section header. Returns the byte
// offset of the `[allow]` line and a boolean indicating whether the
// section was found.
//
// Note: `end` is always `len(content)`. Section-boundary detection (the
// "we've left [allow] into [deny]" decision) is delegated to
// findCommandsLine, which has more context (it scans line-by-line and
// can spot the continuation case for multi-line `commands =\n[ … ]`).
//
// Sections are matched literally — `[allow]`, not `[allow.something]` and
// not `[allowing]`. The closing `]` of `[allow]` must be the last char
// before EOL or whitespace.
func findAllowSection(content []byte) (start int, found bool) {
	// Walk line-by-line so we can correctly match a header line.
	lineStart := 0
	for lineStart <= len(content) {
		lineEndIdx := bytes.IndexByte(content[lineStart:], '\n')
		var stop int
		if lineEndIdx < 0 {
			stop = len(content)
		} else {
			stop = lineStart + lineEndIdx // index of '\n'
		}
		line := content[lineStart:stop]
		trimmed := bytes.TrimLeft(line, " \t")
		if bytes.HasPrefix(trimmed, []byte("[allow]")) {
			// Make sure it's exactly [allow], not a prefix of another
			// section name. After "[allow]" the rest must be whitespace
			// or comment — anything else means it's a longer name.
			rest := trimmed[len("[allow]"):]
			if isOnlyWhitespaceOrComment(rest) {
				return lineStart, true
			}
		}
		if lineEndIdx < 0 {
			return 0, false
		}
		// Advance to the next line. Caller distinguishes "found [allow]"
		// from "didn't" via the boolean return.
		lineStart = stop + 1
	}
	return 0, false
}

func isOnlyWhitespaceOrComment(b []byte) bool {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r') {
		i++
	}
	return i == len(b) || b[i] == '#'
}

// findCommandsLine searches for the `[` that opens the [allow].commands
// array, whether it appears on the same line as `commands =` (the
// common case) or on the next line as a multi-line value continuation.
//
// Returns the byte offset of the `[` and ok=true, or ok=false if no
// commands array is present in [allow].
//
// Recognized shapes:
//
//	[allow]                                    ← start of section
//	commands = [...]                           ← common: array on same line
//	commands =                                 ← rare but legal: array on next line
//	[...]
//
// Limitations (documented as known, not handled):
//
//   - `commands = # comment\n[...]` — a comment between `=` and the
//     value is legal TOML but rare; we treat the line as not ending
//     with `=` and fall through. The array still exists, but pgate add
//     will insert a duplicate `commands =` line, producing invalid TOML.
//     Hand-fix: move the array up onto the same line.
//   - `[allow]\nfoo = [...]\ncommands = [...]` — if an unrelated key in
//     [allow] ends with `=` and the next line starts with `[`, we may
//     mis-attribute that `[` to `commands`. In practice [allow] rarely
//     has multiple top-level keys; if it does, place `commands` first.
//   - Sub-tables / dotted keys ([allow.x], allow.commands = ...) are
//     not supported; the existing config schema only has `commands`.
func findCommandsLine(content []byte, secStart, secEnd int) (arrayStart int, ok bool) {
	i := secStart
	// pendingEq is true when the previous non-blank/non-comment line ended
	// with `=` (after stripping trailing whitespace). When set, the next
	// non-blank/non-comment line that starts with `[` is the array we are
	// looking for, not a new section header.
	pendingEq := false
	for i < secEnd {
		nl := bytes.IndexByte(content[i:secEnd], '\n')
		var lineStop int
		if nl < 0 {
			lineStop = secEnd
		} else {
			lineStop = i + nl
		}
		line := content[i:lineStop]
		trimmed := bytes.TrimLeft(line, " \t\r")

		// Skip blank lines and comments. A blank line also resets
		// pendingEq — TOML doesn't define value continuation across a
		// blank line, so we don't try to span one.
		if len(trimmed) == 0 || trimmed[0] == '#' {
			pendingEq = false
			i = lineStop + 1
			continue
		}

		// Value-continuation case: previous line ended with `=`, this line
		// starts with `[`. The `[` IS the array start.
		if pendingEq && trimmed[0] == '[' {
			leadingWS := len(line) - len(trimmed)
			bracketIdx := bytes.IndexByte(line[leadingWS:], '[')
			if bracketIdx < 0 {
				return 0, false
			}
			return i + leadingWS + bracketIdx, true
		}

		// If this line starts with `[` and we weren't in continuation
		// mode, it's a new section header — we've left [allow].
		if trimmed[0] == '[' {
			return 0, false
		}

		// Look for `commands = [` (with optional whitespace).
		idx := indexWord(trimmed, "commands")
		if idx >= 0 {
			rest := trimmed[idx+len("commands"):]
			rest = bytes.TrimLeft(rest, " \t\r")
			if bytes.HasPrefix(rest, []byte("=")) {
				rest = bytes.TrimLeft(rest[1:], " \t\r")
				if len(rest) > 0 && rest[0] == '[' {
					// Same-line array.
					leadingWS := len(line) - len(trimmed)
					searchFrom := leadingWS + idx + len("commands")
					bracketIdx := bytes.IndexByte(line[searchFrom:], '[')
					if bracketIdx < 0 {
						return 0, false
					}
					return i + searchFrom + bracketIdx, true
				}
				// `=` found but `[` is not on this line. Set pendingEq
				// so the next non-blank line is treated as a continuation.
				pendingEq = true
				i = lineStop + 1
				continue
			}
		}

		// Any other line resets pendingEq.
		pendingEq = false
		i = lineStop + 1
	}
	return 0, false
}

func indexWord(line []byte, word string) int {
	// Returns offset of `word` in `line` where word is preceded by start-of-line
	// or non-identifier character, and followed by non-identifier character.
	// Returns -1 if not found.
	for i := 0; i+len(word) <= len(line); i++ {
		if string(line[i:i+len(word)]) != word {
			continue
		}
		// Boundary check: prev char.
		if i > 0 && isIdentChar(line[i-1]) {
			continue
		}
		// Boundary check: next char.
		if i+len(word) < len(line) && isIdentChar(line[i+len(word)]) {
			continue
		}
		return i
	}
	return -1
}

func isIdentChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') || b == '_' || b == '-'
}

func skipWS(b []byte) int {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t') {
		i++
	}
	return i
}

// findCommandsArray locates the matching `]` of the array that begins at
// content[arrStart] (which is `[`). Returns open and close indices and
// ok=false if no match is found. Used to bound the "inner" array content
// between `[` and `]`.
func findCommandsArray(content []byte, arrStart, secEnd int) (open, close int, ok bool) {
	if arrStart >= secEnd || content[arrStart] != '[' {
		return 0, 0, false
	}
	closeIdx, found := arrayScanner(content, arrStart)
	if !found {
		return 0, 0, false
	}
	return arrStart, closeIdx, true
}

// arrayScanner walks content starting at offset `start` (which must be
// `[`), tracking depth and skipping over TOML strings / literal strings
// / multi-line strings / comments / inline tables, until it finds the
// matching `]`. Returns the offset of that `]` and ok=true. If no match
// is found before EOF, returns ok=false.
//
// This is a deliberate, narrow-purpose scanner: it understands enough
// TOML to step over a `commands = [...]` array without false positives
// from `]` characters inside strings or comments. It does NOT validate
// the surrounding TOML — that is the user's responsibility.
func arrayScanner(content []byte, start int) (close int, ok bool) {
	if start >= len(content) || content[start] != '[' {
		return 0, false
	}
	depth := 0
	i := start
	for i < len(content) {
		c := content[i]
		switch c {
		case '[':
			depth++
			i++
		case ']':
			depth--
			if depth == 0 {
				return i, true
			}
			i++
		case '"':
			next, found := skipBasicString(content, i)
			if !found {
				return 0, false
			}
			i = next
		case '\'':
			next, found := skipLiteralString(content, i)
			if !found {
				return 0, false
			}
			i = next
		case '#':
			// Comment until newline (or EOF).
			nl := bytes.IndexByte(content[i:], '\n')
			if nl < 0 {
				return 0, false
			}
			i += nl + 1
		case '{':
			next, found := skipInlineTable(content, i)
			if !found {
				return 0, false
			}
			i = next
		default:
			i++
		}
	}
	return 0, false
}

// skipBasicString consumes a TOML basic string starting at offset `start`
// (which is `"`). Handles escape sequences and the `"""..."""` multi-line
// form. Returns the offset just past the closing quote(s) and ok=true.
func skipBasicString(content []byte, start int) (next int, ok bool) {
	if content[start] != '"' {
		return start, false
	}
	// Multi-line: """
	if start+2 < len(content) && content[start+1] == '"' && content[start+2] == '"' {
		// Find closing """. Multi-line basic strings allow immediate
		// closing """" as an edge case (5 quotes ending in 3).
		i := start + 3
		for i < len(content) {
			if content[i] == '"' && i+2 < len(content) && content[i+1] == '"' && content[i+2] == '"' {
				// Handle the 5-quote edge case: a """ closing a multi-line
				// string can be """ or """" (the latter means """ inside
				// the string followed by ""). For our needs, accepting the
				// first """ is fine — command specs don't embed """.
				return i + 3, true
			}
			i++
		}
		return start, false
	}
	// Single-line basic string.
	i := start + 1
	for i < len(content) {
		c := content[i]
		if c == '\\' && i+1 < len(content) {
			i += 2
			continue
		}
		if c == '"' {
			return i + 1, true
		}
		if c == '\n' {
			// Unterminated single-line string. We return failure so the
			// caller reports the error rather than walking past the line.
			return start, false
		}
		i++
	}
	return start, false
}

// skipLiteralString consumes a TOML literal string starting at `'`.
func skipLiteralString(content []byte, start int) (next int, ok bool) {
	if content[start] != '\'' {
		return start, false
	}
	// Multi-line: '''
	if start+2 < len(content) && content[start+1] == '\'' && content[start+2] == '\'' {
		i := start + 3
		for i < len(content) {
			if content[i] == '\'' && i+2 < len(content) && content[i+1] == '\'' && content[i+2] == '\'' {
				return i + 3, true
			}
			i++
		}
		return start, false
	}
	// Single-line literal string.
	i := start + 1
	for i < len(content) {
		if content[i] == '\'' {
			return i + 1, true
		}
		if content[i] == '\n' {
			return start, false
		}
		i++
	}
	return start, false
}

// skipInlineTable consumes a TOML inline table starting at `{`. Bracket
// depth is tracked so nested `{...}` or `[...]` arrays inside the inline
// table are stepped over correctly. Strings and comments are skipped too.
func skipInlineTable(content []byte, start int) (next int, ok bool) {
	if content[start] != '{' {
		return start, false
	}
	depth := 0
	i := start
	for i < len(content) {
		c := content[i]
		switch c {
		case '{':
			depth++
			i++
		case '}':
			depth--
			if depth == 0 {
				return i + 1, true
			}
			i++
		case '"':
			next, found := skipBasicString(content, i)
			if !found {
				return 0, false
			}
			i = next
		case '\'':
			next, found := skipLiteralString(content, i)
			if !found {
				return 0, false
			}
			i = next
		case '#':
			nl := bytes.IndexByte(content[i:], '\n')
			if nl < 0 {
				return 0, false
			}
			i += nl + 1
		default:
			i++
		}
	}
	return 0, false
}

// containsBareString reports whether `content[start:end]` (the inside of
// an array, NOT including the brackets) contains a bare-string TOML
// literal equal to spec. Inline tables and comments are skipped.
func containsBareString(content []byte, start, end int, spec string) bool {
	i := start
	for i < end {
		c := content[i]
		switch c {
		case ' ', '\t', '\r', '\n', ',':
			i++
		case '"':
			val, next, ok := readBasicString(content, i)
			if !ok {
				return false
			}
			if val == spec {
				return true
			}
			i = next
		case '\'':
			val, next, ok := readLiteralString(content, i)
			if !ok {
				return false
			}
			if val == spec {
				return true
			}
			i = next
		case '#':
			nl := bytes.IndexByte(content[i:end], '\n')
			if nl < 0 {
				return false
			}
			i += nl + 1
		case '{':
			next, ok := skipInlineTable(content, i)
			if !ok {
				return false
			}
			i = next
		default:
			// Unexpected character. Bail out — the array has something
			// we don't recognize; treat as no-match for safety.
			return false
		}
	}
	return false
}

// readBasicString decodes a TOML basic string starting at offset `start`
// (which is `"`). Returns the decoded value, the offset just past the
// closing quote, and ok=true on success.
func readBasicString(content []byte, start int) (val string, next int, ok bool) {
	if content[start] != '"' {
		return "", start, false
	}
	if start+2 < len(content) && content[start+1] == '"' && content[start+2] == '"' {
		// Multi-line. Skip; command specs are single-line.
		i := start + 3
		for i < len(content) {
			if content[i] == '"' && i+2 < len(content) && content[i+1] == '"' && content[i+2] == '"' {
				return "", i + 3, true
			}
			i++
		}
		return "", start, false
	}
	var b strings.Builder
	i := start + 1
	for i < len(content) {
		c := content[i]
		if c == '\\' && i+1 < len(content) {
			esc := content[i+1]
			switch esc {
			case 'b':
				b.WriteByte('\b')
			case 't':
				b.WriteByte('\t')
			case 'n':
				b.WriteByte('\n')
			case 'f':
				b.WriteByte('\f')
			case 'r':
				b.WriteByte('\r')
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case 'u':
				// \uXXXX — 4 hex digits.
				if i+5 >= len(content) {
					return "", start, false
				}
				var r rune
				_, err := fmt.Sscanf(string(content[i+2:i+6]), "%x", &r)
				if err != nil {
					return "", start, false
				}
				b.WriteRune(r)
				i += 4
			default:
				b.WriteByte('\\')
				b.WriteByte(esc)
			}
			i += 2
			continue
		}
		if c == '"' {
			return b.String(), i + 1, true
		}
		if c == '\n' {
			return "", start, false
		}
		b.WriteByte(c)
		i++
	}
	return "", start, false
}

// readLiteralString decodes a TOML literal string. No escape sequences
// are processed — contents are verbatim.
func readLiteralString(content []byte, start int) (val string, next int, ok bool) {
	if content[start] != '\'' {
		return "", start, false
	}
	if start+2 < len(content) && content[start+1] == '\'' && content[start+2] == '\'' {
		i := start + 3
		for i < len(content) {
			if content[i] == '\'' && i+2 < len(content) && content[i+1] == '\'' && content[i+2] == '\'' {
				return "", i + 3, true
			}
			i++
		}
		return "", start, false
	}
	i := start + 1
	begin := i
	for i < len(content) {
		if content[i] == '\'' {
			return string(content[begin:i]), i + 1, true
		}
		if content[i] == '\n' {
			return "", start, false
		}
		i++
	}
	return "", start, false
}

// buildInsertion constructs the byte string to splice into the array.
// The splice site itself (where in `content` to put the result) is
// returned separately as `insertAt` so the caller can place it precisely.
//
// Shapes selected by array shape:
//
//   - empty (`[]`)                          → insertAt = arrOpen+1; spec
//   - single-line non-empty (`["a","b"]`)   → insertAt = arrClose; `, "spec"`
//   - multi-line, last entry has comma      → insertAt = lastNonWS+1; `\n<indent>"spec"`
//   - multi-line, last entry has no comma   → insertAt = lastNonWS+1; `,\n<indent>"spec"`
//
// For multi-line, `insertAt` is positioned right after the last
// meaningful character (the trailing comma or the closing quote/brace
// of the last entry). This leaves the original trailing whitespace and
// the closing `]` exactly where they were, which avoids the
// double-newline "blank line between entries" artifact that a naïve
// "always prefix with \n" approach produces.
func buildInsertion(inner []byte, arrOpen, arrClose int, spec string) (insertAt int, insertion []byte) {
	encoded := tomlEncodeString(spec)

	if isOnlyWSAndCommas(inner) {
		// Empty array: insert right after `[`. Trailing whitespace and
		// the closing `]` stay where they are.
		return arrOpen + 1, []byte(encoded)
	}

	if !bytes.Contains(inner, []byte{'\n'}) {
		// Single-line non-empty: insert `, "spec"` right before `]`.
		return arrClose, []byte(", " + encoded)
	}

	// Multi-line. Find the offset within `inner` of the last non-whitespace
	// character. We insert immediately AFTER it, so trailing whitespace
	// and the closing `]` are preserved verbatim.
	lastNonWS := -1
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			lastNonWS = i
		}
	}
	if lastNonWS < 0 {
		// Should be impossible: isOnlyWSAndCommas would have caught this.
		return arrClose, []byte(encoded)
	}

	indent := detectClosingIndent(inner)
	hasTrailingComma := inner[lastNonWS] == ','

	var b strings.Builder
	if !hasTrailingComma {
		b.WriteByte(',')
	}
	b.WriteByte('\n')
	b.WriteString(indent)
	b.WriteString(encoded)
	return arrOpen + 1 + lastNonWS + 1, []byte(b.String())
}

func isOnlyWSAndCommas(b []byte) bool {
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' && c != ',' {
			return false
		}
	}
	return true
}

// detectClosingIndent returns the leading whitespace used by entries
// inside the array. We sample the first non-empty line of `inner` (the
// content between `[` and `]`); for the common multi-line shape where
// entries are indented one level deeper than the closing bracket, this
// gives us the entry indent. Falls back to "" (no indent) if `inner` is
// a single-line array or has no detectable entry.
func detectClosingIndent(inner []byte) string {
	// Walk line by line looking for the first line that has any non-whitespace
	// content (a real entry or a comment). Return that line's leading
	// whitespace.
	for i := 0; i < len(inner); {
		nl := bytes.IndexByte(inner[i:], '\n')
		var stop int
		if nl < 0 {
			stop = len(inner)
		} else {
			stop = i + nl
		}
		line := inner[i:stop]
		trimmed := bytes.TrimLeft(line, " \t\r")
		if len(trimmed) > 0 && trimmed[0] != '#' {
			return string(line[:len(line)-len(trimmed)])
		}
		if nl < 0 {
			break
		}
		i = stop + 1
	}
	return ""
}

// lineEnd returns the offset just past the next `\n` at or after `start`,
// or len(content) if no newline is found before EOF. Used to skip a
// complete line (header + trailing newline) in O(1) amortized.
func lineEnd(content []byte, start int) int {
	nl := bytes.IndexByte(content[start:], '\n')
	if nl < 0 {
		return len(content)
	}
	return start + nl + 1
}

// tomlEncodeString returns the TOML basic-string representation of s
// (https://toml.io/en/v1.0.0#string). Output is always double-quoted;
// `\`, `"`, and control characters are escaped per the spec:
//
//	\b \t \n \f \r \" \\
//	\u0000 .. \u001F, \u007F → \uXXXX
//
// We hand-roll the encoder (rather than reusing go-toml/v2's Marshal)
// for three reasons: (1) Marshal can't encode a top-level string, only
// a struct/array/slice, so we'd need a wrapper struct and an awkward
// extraction step; (2) the format we want is always double-quoted for
// predictability — Marshal picks literal strings (single-quoted) by
// default which would make output style depend on the spec's contents;
// (3) this is the only place we emit TOML, so a 30-line helper keeps
// the escape logic visible at the call site.
func tomlEncodeString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
