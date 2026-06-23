package analyze

import (
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
		// Extract this command invocation
		if cmd := extractCallExpr(n); cmd != nil {
			*commands = append(*commands, *cmd)
		}
		// Also check all word parts for command substitutions
		for _, arg := range n.Args {
			walkWordParts(arg.Parts, commands)
		}
		for _, assign := range n.Assigns {
			if assign.Value != nil {
				walkWordParts(assign.Value.Parts, commands)
			}
		}

	case *syntax.BinaryCmd:
		// &&, ||, | — check both sides
		walkCmd(n.X, commands)
		walkCmd(n.Y, commands)

	case *syntax.Subshell:
		walkStmts(n.Stmts, commands)

	case *syntax.Block:
		walkStmts(n.Stmts, commands)

	case *syntax.IfClause:
		walkStmts(n.Cond, commands)
		walkStmts(n.Then, commands)
		if n.Else != nil {
			walkCmd(&syntax.Stmt{Cmd: n.Else}, commands)
		}

	case *syntax.ForClause:
		if n.Loop != nil {
			walkLoop(n.Loop, commands)
		}
		walkStmts(n.Do, commands)

	case *syntax.WhileClause:
		walkStmts(n.Cond, commands)
		walkStmts(n.Do, commands)

	case *syntax.CaseClause:
		for _, item := range n.Items {
			walkStmts(item.Stmts, commands)
		}

	case *syntax.FuncDecl:
		walkCmd(n.Body, commands)

	case *syntax.ArithmCmd:
		walkArithmExpr(n.X, commands)

	case *syntax.TestClause:
		walkTestExpr(n.X, commands)
	}

	// Check redirects for heredocs with command substitutions
	for _, redir := range stmt.Redirs {
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
func (c ExtractedCommand) IsPrefixMatch(prefix []string) bool {
	if len(prefix) == 0 {
		return false
	}
	if len(prefix) > len(c.Tokens) {
		return false
	}
	for i, p := range prefix {
		if c.Tokens[i] != p {
			return false
		}
	}
	return true
}
