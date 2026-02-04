package parser

import (
	"testing"

	"github.com/cedar-policy/cedar-go/internal/schema/token"
)

// TestLexerCoverage exercises all lexer code paths for maximum coverage
func TestLexerCoverage(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		tokens []token.Type
	}{
		// All keywords
		{"keyword action", "action", []token.Type{token.ACTION}},
		{"keyword appliesTo", "appliesTo", []token.Type{token.APPLIESTO}},
		{"keyword context", "context", []token.Type{token.CONTEXT}},
		{"keyword entity", "entity", []token.Type{token.ENTITY}},
		{"keyword enum", "enum", []token.Type{token.ENUM}},
		{"keyword in", "in", []token.Type{token.IN}},
		{"keyword namespace", "namespace", []token.Type{token.NAMESPACE}},
		{"keyword principal", "principal", []token.Type{token.PRINCIPAL}},
		{"keyword resource", "resource", []token.Type{token.RESOURCE}},
		{"keyword tags", "tags", []token.Type{token.TAGS}},
		{"keyword type", "type", []token.Type{token.TYPE}},

		// All punctuation tokens
		{"double colon", "::", []token.Type{token.DOUBLECOLON}},
		{"single colon", ":", []token.Type{token.COLON}},
		{"question mark", "?", []token.Type{token.QUESTION}},
		{"at sign", "@", []token.Type{token.AT}},
		{"left angle", "<", []token.Type{token.LEFTANGLE}},
		{"right angle", ">", []token.Type{token.RIGHTANGLE}},
		{"equals", "=", []token.Type{token.EQUALS}},
		{"semicolon", ";", []token.Type{token.SEMICOLON}},
		{"comma", ",", []token.Type{token.COMMA}},
		{"left paren", "(", []token.Type{token.LEFTPAREN}},
		{"right paren", ")", []token.Type{token.RIGHTPAREN}},
		{"left bracket", "[", []token.Type{token.LEFTBRACKET}},
		{"right bracket", "]", []token.Type{token.RIGHTBRACKET}},
		{"left brace", "{", []token.Type{token.LEFTBRACE}},
		{"right brace", "}", []token.Type{token.RIGHTBRACE}},

		// Identifiers with keyword prefixes (should be IDENT, not keywords)
		{"ident starting with a", "abc", []token.Type{token.IDENT}},
		{"ident starting with ac", "actual", []token.Type{token.IDENT}},
		{"ident starting with act", "activate", []token.Type{token.IDENT}},
		{"ident starting with acti", "activism", []token.Type{token.IDENT}},
		{"ident starting with actio", "actionable", []token.Type{token.IDENT}},
		{"ident starting with ap", "apple", []token.Type{token.IDENT}},
		{"ident starting with app", "application", []token.Type{token.IDENT}},
		{"ident starting with appl", "appliance", []token.Type{token.IDENT}},
		{"ident starting with appli", "applied", []token.Type{token.IDENT}},
		{"ident starting with applie", "applier", []token.Type{token.IDENT}},
		{"ident starting with applies", "applies", []token.Type{token.IDENT}},
		{"ident starting with appliesT", "appliesToo", []token.Type{token.IDENT}},
		{"ident starting with c", "cat", []token.Type{token.IDENT}},
		{"ident starting with co", "coral", []token.Type{token.IDENT}},
		{"ident starting with con", "concrete", []token.Type{token.IDENT}},
		{"ident starting with cont", "control", []token.Type{token.IDENT}},
		{"ident starting with conte", "content", []token.Type{token.IDENT}},
		{"ident starting with contex", "contexual", []token.Type{token.IDENT}},
		{"ident starting with e", "egg", []token.Type{token.IDENT}},
		{"ident starting with en", "enable", []token.Type{token.IDENT}},
		{"ident starting with ent", "enterprise", []token.Type{token.IDENT}},
		{"ident starting with enti", "entire", []token.Type{token.IDENT}},
		{"ident starting with entit", "entitle", []token.Type{token.IDENT}},
		{"ident starting with enu", "enumerate", []token.Type{token.IDENT}},
		{"ident starting with i", "ice", []token.Type{token.IDENT}},
		{"ident starting with in", "ink", []token.Type{token.IDENT}},
		{"ident starting with n", "name", []token.Type{token.IDENT}},
		{"ident starting with na", "nail", []token.Type{token.IDENT}},
		{"ident starting with nam", "named", []token.Type{token.IDENT}},
		{"ident starting with name", "names", []token.Type{token.IDENT}},
		{"ident starting with names", "nameserver", []token.Type{token.IDENT}},
		{"ident starting with namesp", "namespacer", []token.Type{token.IDENT}},
		{"ident starting with namespa", "namespaced", []token.Type{token.IDENT}},
		{"ident starting with namespac", "namespacing", []token.Type{token.IDENT}},
		{"ident starting with p", "pet", []token.Type{token.IDENT}},
		{"ident starting with pr", "print", []token.Type{token.IDENT}},
		{"ident starting with pri", "private", []token.Type{token.IDENT}},
		{"ident starting with prin", "printer", []token.Type{token.IDENT}},
		{"ident starting with princ", "prince", []token.Type{token.IDENT}},
		{"ident starting with princi", "principle", []token.Type{token.IDENT}},
		{"ident starting with princip", "principled", []token.Type{token.IDENT}},
		{"ident starting with principa", "principals", []token.Type{token.IDENT}},
		{"ident starting with r", "run", []token.Type{token.IDENT}},
		{"ident starting with re", "red", []token.Type{token.IDENT}},
		{"ident starting with res", "rest", []token.Type{token.IDENT}},
		{"ident starting with reso", "resolve", []token.Type{token.IDENT}},
		{"ident starting with resou", "resouce", []token.Type{token.IDENT}},
		{"ident starting with resour", "resources", []token.Type{token.IDENT}},
		{"ident starting with resourc", "resourced", []token.Type{token.IDENT}},
		{"ident starting with t", "top", []token.Type{token.IDENT}},
		{"ident starting with ta", "table", []token.Type{token.IDENT}},
		{"ident starting with tag", "tagged", []token.Type{token.IDENT}},
		{"ident starting with ty", "typing", []token.Type{token.IDENT}},
		{"ident starting with typ", "typed", []token.Type{token.IDENT}},

		// Identifiers with various characters
		{"ident with underscore", "_test", []token.Type{token.IDENT}},
		{"ident with numbers", "test123", []token.Type{token.IDENT}},
		{"ident uppercase", "TEST", []token.Type{token.IDENT}},
		{"ident mixed case", "TestCase", []token.Type{token.IDENT}},

		// Comments
		{"line comment", "// this is a comment", []token.Type{token.COMMENT}},
		{"comment with special chars", "// @#$%^&*()", []token.Type{token.COMMENT}},
		{"comment at EOF", "//", []token.Type{token.COMMENT}},

		// Whitespace handling
		{"spaces and tabs", "  \t  action", []token.Type{token.ACTION}},
		{"multiple newlines", "\n\n\naction", []token.Type{token.ACTION}},
		{"CRLF newlines", "\r\naction", []token.Type{token.ACTION}},

		// Strings with escape sequences
		{"string with double quote escape", `"hello\"world"`, []token.Type{token.STRING}},
		{"string with single quote escape", `"hello\'world"`, []token.Type{token.STRING}},
		{"string with backslash escape", `"hello\\world"`, []token.Type{token.STRING}},
		{"string with null escape", `"hello\0world"`, []token.Type{token.STRING}},
		{"string with newline escape", `"hello\nworld"`, []token.Type{token.STRING}},
		{"string with carriage return escape", `"hello\rworld"`, []token.Type{token.STRING}},
		{"string with tab escape", `"hello\tworld"`, []token.Type{token.STRING}},

		// Unicode escapes
		{"unicode escape single digit", `"\u{1}"`, []token.Type{token.STRING}},
		{"unicode escape two digits", `"\u{1f}"`, []token.Type{token.STRING}},
		{"unicode escape three digits", `"\u{1f0}"`, []token.Type{token.STRING}},
		{"unicode escape four digits", `"\u{1f00}"`, []token.Type{token.STRING}},
		{"unicode escape uppercase", `"\u{1F}"`, []token.Type{token.STRING}},
		{"unicode escape mixed case", `"\u{aF}"`, []token.Type{token.STRING}},

		// Complex expressions
		{"full namespace", "namespace Foo::Bar {}", []token.Type{
			token.NAMESPACE, token.IDENT, token.DOUBLECOLON, token.IDENT,
			token.LEFTBRACE, token.RIGHTBRACE,
		}},
		{"entity with type", "entity User in [Group]", []token.Type{
			token.ENTITY, token.IDENT, token.IN, token.LEFTBRACKET,
			token.IDENT, token.RIGHTBRACKET,
		}},
		{"action with applies", "action Read appliesTo { principal: User }", []token.Type{
			token.ACTION, token.IDENT, token.APPLIESTO, token.LEFTBRACE,
			token.PRINCIPAL, token.COLON, token.IDENT, token.RIGHTBRACE,
		}},
		{"type declaration", "type Id = String;", []token.Type{
			token.TYPE, token.IDENT, token.EQUALS, token.IDENT, token.SEMICOLON,
		}},
		{"optional type", "attr?: String", []token.Type{
			token.IDENT, token.QUESTION, token.COLON, token.IDENT,
		}},
		{"annotation", "@doc(\"description\")", []token.Type{
			token.AT, token.IDENT, token.LEFTPAREN, token.STRING, token.RIGHTPAREN,
		}},
		{"set type", "Set<String>", []token.Type{
			token.IDENT, token.LEFTANGLE, token.IDENT, token.RIGHTANGLE,
		}},
		{"entity with tags", "entity User tags String", []token.Type{
			token.ENTITY, token.IDENT, token.TAGS, token.IDENT,
		}},

		// Additional coverage for keyword boundary detection
		{"keyword followed by special char", "action;", []token.Type{token.ACTION, token.SEMICOLON}},
		{"keyword followed by digit", "entity1", []token.Type{token.IDENT}},
		{"keyword followed by uppercase", "actionA", []token.Type{token.IDENT}},
		{"keyword with underscore suffix", "action_", []token.Type{token.IDENT}},
		{"multiple spaces", "   action   ", []token.Type{token.ACTION}},
		{"tabs only", "\t\taction", []token.Type{token.ACTION}},

		// Test all keyword boundary conditions
		{"namespace boundary", "namespace;", []token.Type{token.NAMESPACE, token.SEMICOLON}},
		{"entity boundary", "entity;", []token.Type{token.ENTITY, token.SEMICOLON}},
		{"type boundary", "type;", []token.Type{token.TYPE, token.SEMICOLON}},
		{"in boundary", "in;", []token.Type{token.IN, token.SEMICOLON}},
		{"tags boundary", "tags;", []token.Type{token.TAGS, token.SEMICOLON}},
		{"appliesTo boundary", "appliesTo;", []token.Type{token.APPLIESTO, token.SEMICOLON}},
		{"principal boundary", "principal;", []token.Type{token.PRINCIPAL, token.SEMICOLON}},
		{"resource boundary", "resource;", []token.Type{token.RESOURCE, token.SEMICOLON}},
		{"context boundary", "context;", []token.Type{token.CONTEXT, token.SEMICOLON}},
		{"enum boundary", "enum;", []token.Type{token.ENUM, token.SEMICOLON}},

		// Test identifiers ending at various boundaries
		{"ident ending at special", "abc{", []token.Type{token.IDENT, token.LEFTBRACE}},
		{"ident ending at bracket", "xyz[", []token.Type{token.IDENT, token.LEFTBRACKET}},
		{"ident with digits in middle", "a1b2c3", []token.Type{token.IDENT}},
		{"context type", "context: {}", []token.Type{
			token.CONTEXT, token.COLON, token.LEFTBRACE, token.RIGHTBRACE,
		}},
		{"enum declaration", "enum Status = [\"active\", \"inactive\"]", []token.Type{
			token.ENUM, token.IDENT, token.EQUALS, token.LEFTBRACKET,
			token.STRING, token.COMMA, token.STRING, token.RIGHTBRACKET,
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewLexer("<test>", []byte(tt.input))
			tokens := l.All()

			if len(l.Errors) > 0 {
				t.Errorf("Unexpected errors: %v", l.Errors)
			}

			if len(tokens) != len(tt.tokens) {
				t.Errorf("Token count mismatch: got %d, want %d", len(tokens), len(tt.tokens))
				for i, tok := range tokens {
					t.Logf("  token[%d]: %s %q", i, tok.Type, tok.String())
				}
				return
			}

			for i, want := range tt.tokens {
				if tokens[i].Type != want {
					t.Errorf("Token[%d]: got %s, want %s", i, tokens[i].Type, want)
				}
			}
		})
	}
}

// TestLexerErrors tests error handling paths
func TestLexerErrors(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantError bool
	}{
		// Error cases
		{"unterminated string", `"unterminated`, true},
		{"invalid escape in string", `"invalid \z escape"`, true},
		{"standalone carriage return", "test\ralone", true},
		{"newline in string", "\"hello\nworld\"", true},
		{"standalone slash", "test / other", true},
		{"invalid unicode escape empty", `"\u{}"`, true},
		{"invalid unicode escape no brace", `"\u1234"`, true},
		{"unrecognized character", "\x01", true},
		{"backtick character", "`", true},
		{"ident followed by backtick", "abc`", true},

		// Valid cases that might seem like errors
		{"escaped backslash at end", `"test\\"`, false},
		{"empty string", `""`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewLexer("<test>", []byte(tt.input))
			l.All()

			hasError := len(l.Errors) > 0
			if hasError != tt.wantError {
				if tt.wantError {
					t.Errorf("Expected error but got none")
				} else {
					t.Errorf("Unexpected error: %v", l.Errors)
				}
			}
		})
	}
}

// TestLexerStringEscapes specifically tests all string escape sequences
func TestLexerStringEscapes(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`"\""`, "\"\"\""},      // escaped double quote -> "
		{`"\'"`, "\"'\""},       // escaped single quote -> '
		{`"\\"`, "\"\\\""},      // escaped backslash -> \
		{`"\0"`, "\"\x00\""},    // null
		{`"\n"`, "\"\n\""},      // newline
		{`"\r"`, "\"\r\""},      // carriage return
		{`"\t"`, "\"\t\""},      // tab
		{`"\u{0}"`, "\"\x00\""}, // unicode null
		{`"\u{a}"`, "\"\n\""},   // unicode newline (0x0a)
		{`"\u{0a}"`, "\"\n\""},  // unicode with leading zero
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			l := NewLexer("<test>", []byte(tt.input))
			tokens := l.All()

			if len(l.Errors) > 0 {
				t.Errorf("Unexpected errors: %v", l.Errors)
				return
			}

			if len(tokens) != 1 {
				t.Errorf("Expected 1 token, got %d", len(tokens))
				return
			}

			if tokens[0].Type != token.STRING {
				t.Errorf("Expected STRING token, got %s", tokens[0].Type)
				return
			}

			if tokens[0].String() != tt.expected {
				t.Errorf("String value mismatch:\n  got:  %q\n  want: %q", tokens[0].String(), tt.expected)
			}
		})
	}
}

// TestLexerPositionTracking tests that line/column tracking works correctly
func TestLexerPositionTracking(t *testing.T) {
	input := "namespace\nFoo\r\n{\n}"
	l := NewLexer("test.cedarschema", []byte(input))
	tokens := l.All()

	expected := []struct {
		tok    token.Type
		line   int
		column int
	}{
		{token.NAMESPACE, 1, 1},
		{token.IDENT, 2, 1},
		{token.LEFTBRACE, 3, 1},
		{token.RIGHTBRACE, 4, 1},
	}

	if len(tokens) != len(expected) {
		t.Fatalf("Token count mismatch: got %d, want %d", len(tokens), len(expected))
	}

	for i, want := range expected {
		got := tokens[i]
		if got.Type != want.tok {
			t.Errorf("Token[%d] type: got %s, want %s", i, got.Type, want.tok)
		}
		if got.Pos.Line != want.line {
			t.Errorf("Token[%d] line: got %d, want %d", i, got.Pos.Line, want.line)
		}
		if got.Pos.Column != want.column {
			t.Errorf("Token[%d] column: got %d, want %d", i, got.Pos.Column, want.column)
		}
	}
}
