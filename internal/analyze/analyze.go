package analyze

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ExtractedCommand represents one simple command found in the AST.
type ExtractedCommand struct {
	Tokens []string // canonical tokens: ["git", "log", "--oneline"]
	Raw    string   // space-joined tokens for easy matching
}

// ExtractCommands parses a shell command string and returns ALL commands
// that would be executed, including those inside $(...), `...`, (...) etc.
func ExtractCommands(cmd string) ([]ExtractedCommand, error) {
	parser := syntax.NewParser()
	file, err := parser.Parse(strings.NewReader(cmd), "")
	if err != nil {
		return nil, err
	}

	var commands []ExtractedCommand
	walkStmts(file.Stmts, &commands)
	return commands, nil
}

// walkStmts extracts commands from a list of statements.
func walkStmts(stmts []*syntax.Stmt, commands *[]ExtractedCommand) {
	for _, stmt := range stmts {
		walkCmd(stmt, commands)
	}
}

// walkCmd extracts commands from a single statement.
func walkCmd(stmt *syntax.Stmt, commands *[]ExtractedCommand) {
	if stmt == nil || stmt.Cmd == nil {
		return
	}

	switch n := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		handleCallExpr(n, commands)
	case *syntax.BinaryCmd:
		// &&, ||, | — check both sides
		walkCmd(n.X, commands)
		walkCmd(n.Y, commands)
	case *syntax.Subshell:
		walkStmts(n.Stmts, commands)
	case *syntax.Block:
		walkStmts(n.Stmts, commands)
	case *syntax.IfClause:
		handleIfClause(n, commands)
	case *syntax.ForClause:
		handleForClause(n, commands)
	case *syntax.WhileClause:
		walkStmts(n.Cond, commands)
		walkStmts(n.Do, commands)
	case *syntax.CaseClause:
		handleCaseClause(n, commands)
	case *syntax.FuncDecl:
		walkCmd(n.Body, commands)
	case *syntax.ArithmCmd:
		walkArithmExpr(n.X, commands)
	case *syntax.TestClause:
		walkTestExpr(n.X, commands)
	}

	walkRedirs(stmt.Redirs, commands)
}

// handleCallExpr extracts the command itself and walks every word part
// (in args and assignments) for nested command substitutions.
func handleCallExpr(n *syntax.CallExpr, commands *[]ExtractedCommand) {
	if cmd := extractCallExpr(n); cmd != nil {
		*commands = append(*commands, *cmd)
	}
	for _, arg := range n.Args {
		walkWordParts(arg.Parts, commands)
	}
	for _, assign := range n.Assigns {
		if assign.Value != nil {
			walkWordParts(assign.Value.Parts, commands)
		}
	}
}

// handleIfClause walks the cond/then arms and, if present, the else arm.
func handleIfClause(n *syntax.IfClause, commands *[]ExtractedCommand) {
	walkStmts(n.Cond, commands)
	walkStmts(n.Then, commands)
	if n.Else != nil {
		walkCmd(&syntax.Stmt{Cmd: n.Else}, commands)
	}
}

// handleForClause walks the loop header (if any) and the body statements.
func handleForClause(n *syntax.ForClause, commands *[]ExtractedCommand) {
	if n.Loop != nil {
		walkLoop(n.Loop, commands)
	}
	walkStmts(n.Do, commands)
}

// handleCaseClause walks the statement list of every match arm.
func handleCaseClause(n *syntax.CaseClause, commands *[]ExtractedCommand) {
	for _, item := range n.Items {
		walkStmts(item.Stmts, commands)
	}
}

// walkRedirs inspects every redirect's word parts (including heredoc
// bodies) for command substitutions.
func walkRedirs(redirs []*syntax.Redirect, commands *[]ExtractedCommand) {
	for _, redir := range redirs {
		if redir.Hdoc != nil {
			walkWordParts(redir.Hdoc.Parts, commands)
		}
		if redir.Word != nil {
			walkWordParts(redir.Word.Parts, commands)
		}
	}
}

// walkWordParts recursively inspects word parts for command substitutions.
func walkWordParts(parts []syntax.WordPart, commands *[]ExtractedCommand) {
	for _, part := range parts {
		switch p := part.(type) {
		case *syntax.CmdSubst:
			walkStmts(p.Stmts, commands)
		case *syntax.ProcSubst:
			walkStmts(p.Stmts, commands)
		case *syntax.DblQuoted:
			walkWordParts(p.Parts, commands)
		case *syntax.ParamExp:
			if p.NestedParam != nil {
				if cmdSubst, ok := p.NestedParam.(*syntax.CmdSubst); ok {
					walkStmts(cmdSubst.Stmts, commands)
				}
			}
		}
	}
}

// walkLoop extracts commands from for/select loop headers.
func walkLoop(loop syntax.Loop, commands *[]ExtractedCommand) {
	switch l := loop.(type) {
	case *syntax.WordIter:
		// for x in words — no hidden commands usually
	case *syntax.CStyleLoop:
		if l.Init != nil {
			walkCallExprMaybe(l.Init, commands)
		}
		if l.Cond != nil {
			walkArithmExpr(l.Cond, commands)
		}
		if l.Post != nil {
			walkCallExprMaybe(l.Post, commands)
		}
	}
}

// walkCallExprMaybe handles CallExpr that might be an ArithmExpr.
func walkCallExprMaybe(n syntax.Node, commands *[]ExtractedCommand) {
	if call, ok := n.(*syntax.CallExpr); ok {
		if cmd := extractCallExpr(call); cmd != nil {
			*commands = append(*commands, *cmd)
		}
	}
}

// walkArithmExpr handles arithmetic expressions (which may contain call-like things).
func walkArithmExpr(expr syntax.ArithmExpr, commands *[]ExtractedCommand) {
	switch e := expr.(type) {
	case *syntax.BinaryArithm:
		walkArithmExpr(e.X, commands)
		walkArithmExpr(e.Y, commands)
	case *syntax.UnaryArithm:
		walkArithmExpr(e.X, commands)
	case *syntax.ParenArithm:
		walkArithmExpr(e.X, commands)
	}
}

// walkTestExpr handles test expressions.
func walkTestExpr(expr syntax.TestExpr, commands *[]ExtractedCommand) {
	switch e := expr.(type) {
	case *syntax.BinaryTest:
		walkTestExpr(e.X, commands)
		walkTestExpr(e.Y, commands)
	case *syntax.UnaryTest:
		walkTestExpr(e.X, commands)
	case *syntax.ParenTest:
		walkTestExpr(e.X, commands)
	}
}

// extractCallExpr converts a CallExpr into extracted command tokens.
func extractCallExpr(call *syntax.CallExpr) *ExtractedCommand {
	tokens := make([]string, 0, len(call.Args))
	for _, arg := range call.Args {
		tokens = append(tokens, wordToToken(arg))
	}
	if len(tokens) == 0 {
		return nil
	}
	return &ExtractedCommand{
		Tokens: tokens,
		Raw:    strings.Join(tokens, " "),
	}
}

// wordToToken converts a Word to its best-effort string representation.
func wordToToken(w *syntax.Word) string {
	if lit := w.Lit(); lit != "" {
		return lit
	}
	var sb strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				if lit, ok := inner.(*syntax.Lit); ok {
					sb.WriteString(lit.Value)
				}
			}
		case *syntax.ParamExp:
			if p.Param != nil {
				sb.WriteString("${")
				sb.WriteString(p.Param.Value)
				sb.WriteString("}")
			}
		case *syntax.CmdSubst:
			sb.WriteString("$(...)")
		case *syntax.ProcSubst:
			sb.WriteString("<(...)")
		}
	}
	return sb.String()
}

// CommandName returns the first token (the command name).
func (c ExtractedCommand) Name() string {
	if len(c.Tokens) == 0 {
		return ""
	}
	return c.Tokens[0]
}

// HasFlag checks if a specific flag appears anywhere in the command tokens.
func (c ExtractedCommand) HasFlag(flag string) bool {
	isShort := len(flag) == 2 && flag[0] == '-'
	for _, tok := range c.Tokens[1:] {
		if tok == "--" {
			break
		}
		// Exact match or --long-flag=value form
		if tok == flag || strings.HasPrefix(tok, flag+"=") {
			return true
		}
		// Short flag with suffix: -i.bak, -j4, -rf etc
		// Match if flag is like "-i" and token starts with "-i" and
		// the character after "-i" is not another "-" or "="
		if isShort && strings.HasPrefix(tok, flag) && len(tok) > len(flag) {
			after := tok[len(flag)]
			if after != '=' && after != '-' {
				return true
			}
		}
	}
	return false
}

// IsPrefixMatch checks if the command starts with the given prefix tokens.
// When the first token is a path (/bin/ls, ./ls, ../tools/bin/ls, ~/bin/ls),
// also matches the basename (ls).
func (c ExtractedCommand) IsPrefixMatch(prefix []string) bool {
	if len(prefix) == 0 || len(prefix) > len(c.Tokens) {
		return false
	}
	for i, p := range prefix {
		if c.Tokens[i] != p {
			// Path-like token: try matching basename instead
			if i == 0 {
				base := filepath.Base(c.Tokens[0])
				if base != c.Tokens[0] && base != "." && base == p {
					continue
				}
			}
			return false
		}
	}
	return true
}

// IsSuffixMatch checks if the command ends with the given suffix tokens.
func (c ExtractedCommand) IsSuffixMatch(suffix []string) bool {
	if len(suffix) == 0 || len(suffix) > len(c.Tokens) {
		return false
	}
	offset := len(c.Tokens) - len(suffix)
	for i, s := range suffix {
		if c.Tokens[offset+i] != s {
			return false
		}
	}
	return true
}

// Match checks a pattern against the command. Patterns starting with "*" use
// suffix matching; all other patterns use prefix matching.
func (c ExtractedCommand) Match(pattern []string) bool {
	if len(pattern) == 0 {
		return false
	}
	if pattern[0] == "*" {
		return c.IsSuffixMatch(pattern[1:])
	}
	return c.IsPrefixMatch(pattern)
}

// NonFlagArgs returns all non-flag tokens in the command. The POSIX end-of-
// options marker `--` ends flag scanning: every token after it is treated as
// a positional argument, even if it starts with a dash.
func (c ExtractedCommand) NonFlagArgs() []string {
	var out []string
	afterDashDash := false
	for _, tok := range c.Tokens[1:] {
		if tok == "--" {
			afterDashDash = true
			continue
		}
		if !afterDashDash && looksLikeFlag(tok) {
			continue
		}
		out = append(out, tok)
	}
	return out
}

// ExpandedFlagSet returns the set of flags present in the command. Short
// option bundles of ≤4 lowercase letters (-rf, -fr, -rfi, -rv) are
// expanded into individual flags. Anything longer with a single dash is
// treated as a GNU long option (-name, -exec) and stored verbatim so it
// can be matched against spec entries like IncludeFlags = ["-exec"].
// True POSIX long options (--name, --name=value) are stored as-is. Anything
// after `--` is ignored.
func (c ExtractedCommand) ExpandedFlagSet() map[string]struct{} {
	out := make(map[string]struct{})
	afterDashDash := false
	for _, tok := range c.Tokens[1:] {
		if tok == "--" {
			afterDashDash = true
			continue
		}
		if afterDashDash {
			continue
		}
		if !looksLikeFlag(tok) {
			continue
		}
		if strings.HasPrefix(tok, "--") {
			name := tok
			if i := strings.IndexByte(tok, '='); i >= 0 {
				name = tok[:i]
			}
			out[name] = struct{}{}
			continue
		}
		// Single-dash token: short flag (-x) or short bundle (-rf) or GNU
		// long (-name). Decide by length and composition.
		if len(tok) == 2 {
			out[tok] = struct{}{}
			continue
		}
		if IsShortBundle(tok) {
			for i := 1; i < len(tok); i++ {
				out["-"+string(tok[i])] = struct{}{}
			}
			continue
		}
		// GNU long option (or attached value): store verbatim.
		name := tok
		if i := strings.IndexByte(tok, '='); i >= 0 {
			name = tok[:i]
		}
		out[name] = struct{}{}
	}
	return out
}

// IsShortBundle reports whether tok is a POSIX short-option bundle: a
// leading "-" followed by 2–3 lowercase letters (total length 3–4), e.g.
// -rf, -fr, -rfi, -rv. Anything longer or with uppercase / digits is
// treated as a GNU long option instead. Exported so the rule engine can
// apply the same heuristic when expanding spec-side flags.
func IsShortBundle(tok string) bool {
	if len(tok) < 3 || len(tok) > 4 || tok[0] != '-' {
		return false
	}
	for i := 1; i < len(tok); i++ {
		c := tok[i]
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

func looksLikeFlag(tok string) bool {
	return len(tok) >= 2 && tok[0] == '-' && tok != "-"
}
