package schema

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/cedar-policy/cedar-go/internal/schema/ast"
	"github.com/cedar-policy/cedar-go/internal/schema/parser"
)

// Schema is a description of entities and actions that are allowed for a PolicySet. They can be used to validate policies
// and entity definitions and also provide documentation.
//
// Schema is immutable after construction and safe for concurrent use by multiple goroutines.
// Use NewFromJSON or NewFromCedar to create a Schema.
type Schema struct {
	jsonSchema ast.JSONSchema
}

// NewFromCedar parses the human-readable schema from src and returns a Schema.
// Returns an error if the schema is invalid.
//
// Any errors returned will have file positions matching filename.
func NewFromCedar(filename string, src []byte) (*Schema, error) {
	humanSchema, err := parser.ParseFile(filename, src)
	if err != nil {
		return nil, err
	}
	return &Schema{
		jsonSchema: ast.ConvertHuman2JSON(humanSchema),
	}, nil
}

// NewFromJSON parses the JSON schema from src and returns a Schema.
// Returns an error if the JSON is not valid schema JSON.
func NewFromJSON(src []byte) (*Schema, error) {
	var jsonSchema ast.JSONSchema
	if err := json.Unmarshal(src, &jsonSchema); err != nil {
		return nil, err
	}
	return &Schema{
		jsonSchema: jsonSchema,
	}, nil
}

// MarshalCedar serializes the schema into the human readable format.
func (s *Schema) MarshalCedar() ([]byte, error) {
	if s.jsonSchema == nil {
		return nil, fmt.Errorf("schema is empty")
	}
	humanSchema := ast.ConvertJSON2Human(s.jsonSchema)
	var buf bytes.Buffer
	err := ast.Format(humanSchema, &buf)
	return buf.Bytes(), err
}

// MarshalJSON serializes the schema into the JSON format.
func (s *Schema) MarshalJSON() ([]byte, error) {
	if s.jsonSchema == nil {
		return nil, nil
	}
	return json.Marshal(s.jsonSchema)
}
