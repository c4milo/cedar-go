package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/cedar-policy/cedar-go/internal/schema/ast"
	"github.com/cedar-policy/cedar-go/internal/schema/parser"
)

// Schema is a description of entities and actions that are allowed for a PolicySet. They can be used to validate policies
// and entity definitions and also provide documentation.
//
// Schemas can be represented in either JSON (*JSON functions) or Human-readable formats (*Cedar functions) just like policies.
// Marshalling and unmarshalling between the formats is allowed.
//
// Schema is safe for concurrent use by multiple goroutines. Like Rust Cedar, Schema is
// immutable after construction - all conversions happen at Unmarshal time, and Marshal
// operations are pure reads.
type Schema struct {
	mu         sync.RWMutex
	filename   string
	jsonSchema ast.JSONSchema // canonical representation, always populated after Unmarshal
}

// UnmarshalCedar parses the human-readable schema from src, converts it to the internal
// representation, and returns an error if the schema is invalid.
//
// Any errors returned will have file positions matching filename.
func (s *Schema) UnmarshalCedar(src []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	humanSchema, err := parser.ParseFile(s.filename, src)
	if err != nil {
		return err
	}
	// Convert to JSON representation immediately (like Rust Cedar)
	s.jsonSchema = ast.ConvertHuman2JSON(humanSchema)
	return nil
}

// MarshalCedar serializes the schema into the human readable format.
func (s *Schema) MarshalCedar() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.jsonSchema == nil {
		return nil, fmt.Errorf("schema is empty")
	}
	// Convert to human format for output (no mutation, pure read)
	humanSchema := ast.ConvertJSON2Human(s.jsonSchema)
	var buf bytes.Buffer
	err := ast.Format(humanSchema, &buf)
	return buf.Bytes(), err
}

// UnmarshalJSON deserializes the JSON schema from src or returns an error if the JSON is not valid schema JSON.
func (s *Schema) UnmarshalJSON(src []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var jsonSchema ast.JSONSchema
	if err := json.Unmarshal(src, &jsonSchema); err != nil {
		return err
	}
	s.jsonSchema = jsonSchema
	return nil
}

// MarshalJSON serializes the schema into the JSON format.
func (s *Schema) MarshalJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.jsonSchema == nil {
		return nil, nil
	}
	return json.Marshal(s.jsonSchema)
}

// SetFilename sets the filename for the schema in the returned error messages from Unmarshal*.
func (s *Schema) SetFilename(filename string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.filename = filename
}
