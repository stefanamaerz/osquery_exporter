package model

import (
	"fmt"
	"strings"
	"unicode"
)

// mutatingKeywords are SQL statement starters that can modify state or data.
// They are rejected by validateReadOnlyQuery regardless of position.
var mutatingKeywords = map[string]struct{}{
	"insert":   {},
	"update":   {},
	"delete":   {},
	"drop":     {},
	"create":   {},
	"alter":    {},
	"truncate": {},
	"attach":   {},
	"detach":   {},
	"pragma":   {},
}

// validateReadOnlyQuery checks that q is a single read-only SQL statement.
// It accepts SELECT and WITH ... SELECT and rejects mutating keywords,
// multiple statements (semicolons), and malformed input.
func validateReadOnlyQuery(q string) error {
	if strings.TrimSpace(q) == "" {
		return fmt.Errorf("query is empty")
	}

	s := newQueryScanner(q)
	depth := 0
	selected := false

	for {
		tok := s.nextToken()
		if tok == "" {
			break
		}

		switch tok {
		case "(":
			depth++
		case ")":
			if depth > 0 {
				depth--
			}
		case ";":
			if depth == 0 {
				return fmt.Errorf("query contains a semicolon; only a single statement is allowed")
			}
		default:
			if depth != 0 {
				continue
			}
			if tok == "select" {
				selected = true
			}
			if _, ok := mutatingKeywords[tok]; ok {
				return fmt.Errorf("query contains mutating keyword %q", tok)
			}
		}
	}

	if !selected {
		return fmt.Errorf("query must be a SELECT statement")
	}
	return nil
}

// queryScanner scans a SQL string and returns low-cased keyword/identifier
// tokens and a few punctuation tokens that matter for validation. It ignores
// whitespace, comments, string literals, numeric literals, and operators.
type queryScanner struct {
	input string
	pos   int
}

func newQueryScanner(input string) *queryScanner {
	return &queryScanner{input: input}
}

func (s *queryScanner) nextToken() string {
	for s.pos < len(s.input) {
		ch := s.input[s.pos]

		// Whitespace.
		if unicode.IsSpace(rune(ch)) {
			s.pos++
			continue
		}

		// Line comment.
		if ch == '-' && s.peek(1) == '-' {
			s.skipUntil('\n')
			continue
		}

		// Block comment.
		if ch == '/' && s.peek(1) == '*' {
			s.skipBlockComment()
			continue
		}

		// String literal (single or double quotes).
		if ch == '\'' || ch == '"' {
			s.skipString(ch)
			continue
		}

		// Numeric literal.
		if unicode.IsDigit(rune(ch)) {
			s.skipNumber()
			continue
		}

		// Identifier or keyword.
		if unicode.IsLetter(rune(ch)) || ch == '_' {
			start := s.pos
			for s.pos < len(s.input) {
				c := s.input[s.pos]
				if unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c)) || c == '_' {
					s.pos++
				} else {
					break
				}
			}
			return strings.ToLower(s.input[start:s.pos])
		}

		// Punctuation we care about.
		s.pos++
		if ch == '(' || ch == ')' || ch == ';' {
			return string(ch)
		}
		// Any other punctuation/operator is ignored.
	}
	return ""
}

func (s *queryScanner) peek(offset int) byte {
	if s.pos+offset >= len(s.input) {
		return 0
	}
	return s.input[s.pos+offset]
}

func (s *queryScanner) skipUntil(ch byte) {
	for s.pos < len(s.input) {
		if s.input[s.pos] == ch {
			s.pos++
			return
		}
		s.pos++
	}
}

func (s *queryScanner) skipBlockComment() {
	// Skip the opening /*
	s.pos += 2
	for s.pos < len(s.input)-1 {
		if s.input[s.pos] == '*' && s.input[s.pos+1] == '/' {
			s.pos += 2
			return
		}
		s.pos++
	}
	s.pos = len(s.input)
}

func (s *queryScanner) skipString(quote byte) {
	// Skip opening quote.
	s.pos++
	for s.pos < len(s.input) {
		if s.input[s.pos] == quote {
			s.pos++
			return
		}
		s.pos++
	}
}

func (s *queryScanner) skipNumber() {
	for s.pos < len(s.input) {
		c := s.input[s.pos]
		if unicode.IsDigit(rune(c)) || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-' {
			s.pos++
		} else {
			break
		}
	}
}
