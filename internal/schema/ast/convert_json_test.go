package ast_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/cedar-policy/cedar-go/internal/schema/ast"
	"github.com/cedar-policy/cedar-go/internal/schema/parser"
	"github.com/cedar-policy/cedar-go/internal/testutil"
)

func TestConvertJsonToHumanRoundtrip(t *testing.T) {
	// Read the example JSON schema from embedded filesystem
	exampleJSON, err := fs.ReadFile(ast.Testdata, "testdata/convert/test_want.json")
	if err != nil {
		t.Fatalf("Error reading example JSON schema: %v", err)
	}

	// Parse the JSON schema
	var jsonSchema ast.JSONSchema
	if err := json.Unmarshal(exampleJSON, &jsonSchema); err != nil {
		t.Fatalf("Error parsing JSON schema: %v", err)
	}

	// Convert to human-readable format and back to JSON
	humanSchema := ast.ConvertJSON2Human(jsonSchema)
	jsonSchema2 := ast.ConvertHuman2JSON(humanSchema)

	// Compare the JSON schemas
	json1, err := json.MarshalIndent(jsonSchema, "", "    ")
	testutil.OK(t, err)

	json2, err := json.MarshalIndent(jsonSchema2, "", "    ")
	testutil.OK(t, err)

	diff := cmp.Diff(string(json1), string(json2))
	testutil.FatalIf(t, diff != "", "mismatch -want +got:\n%v", diff)
}

func TestConvertJsonToHumanEmpty(t *testing.T) {
	// Test with an empty JSON schema
	emptySchema := ast.JSONSchema{}
	humanSchema := ast.ConvertJSON2Human(emptySchema)

	// Format the human-readable schema
	var got bytes.Buffer
	if err := ast.Format(humanSchema, &got); err != nil {
		t.Fatalf("Error formatting schema: %v", err)
	}

	// Should be empty
	if len(got.Bytes()) != 0 {
		t.Errorf("Expected empty output, got: %q", got.String())
	}
}

func TestConvertJsonToHumanControlCharsRoundtrip(t *testing.T) {
	tests := []struct {
		name       string
		actionName string
	}{
		{"del", "\x7f"},
		{"tab", "\t"},
		{"newline", "\n"},
		{"null", "\x00"},
		{"bell", "\a"},
		{"backspace", "\b"},
		{"escape", "\x1b"},
		{"mixed", "ok\x7faction"},
		{"unicode", "\u00e9"},
		{"printable_ascii", "normal"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonSchema := ast.JSONSchema{
				"": {
					Actions: map[string]*ast.JSONAction{
						tt.actionName: {},
					},
				},
			}

			humanSchema := ast.ConvertJSON2Human(jsonSchema)

			var buf bytes.Buffer
			if err := ast.Format(humanSchema, &buf); err != nil {
				t.Fatalf("Format failed: %v", err)
			}

			cedarText := buf.Bytes()

			// Parse the Cedar text back — this is what failed before the fix
			parsed, err := parser.ParseFile("test.cedar", cedarText)
			if err != nil {
				t.Fatalf("ParseFile failed for action %q: %v\nCedar: %s", tt.actionName, err, cedarText)
			}

			// Convert back to JSON and verify the action name survived
			jsonSchema2 := ast.ConvertHuman2JSON(parsed)
			ns, ok := jsonSchema2[""]
			if !ok {
				t.Fatalf("anonymous namespace missing after roundtrip")
			}
			if _, ok := ns.Actions[tt.actionName]; !ok {
				t.Errorf("action name %q lost after roundtrip", tt.actionName)
			}
		})
	}
}

func TestConvertJsonToHumanInvalidType(t *testing.T) {
	// Test with an invalid JSON type - should handle gracefully without panic
	invalidSchema := ast.JSONSchema{
		"": {
			EntityTypes: map[string]*ast.JSONEntity{
				"Test": {
					Shape: &ast.JSONType{
						Type: "InvalidType",
					},
				},
			},
		},
	}

	// Should not panic - invalid types are converted to empty records
	var panicMsg string
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicMsg = fmt.Sprint(r)
			}
		}()
		ast.ConvertJSON2Human(invalidSchema)
	}()

	if panicMsg != "" {
		t.Errorf("expected no panic, got: %s", panicMsg)
	}
}
