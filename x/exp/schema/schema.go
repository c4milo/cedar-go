// Package schema provides schema parsing, serialization, resolution,
// introspection, and authorization query APIs for Cedar schemas.
package schema

import (
	"encoding/json"
	"fmt"

	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/schema/ast"
	schemajson "github.com/cedar-policy/cedar-go/x/exp/schema/internal/json"
	"github.com/cedar-policy/cedar-go/x/exp/schema/internal/parser"
	"github.com/cedar-policy/cedar-go/x/exp/schema/resolved"
)

// Schema is an immutable, eagerly-resolved Cedar schema. After construction,
// all type references are resolved and introspection indexes are precomputed.
type Schema struct {
	// Upstream AST (for marshaling)
	inner *ast.Schema

	// Precomputed from resolved (for introspection/query)
	entityTypes    map[types.EntityType]*EntityTypeInfo
	actionTypes    map[types.EntityUID]*ActionTypeInfo
	commonTypes    map[string]CedarType
	principals     []types.EntityType
	resources      []types.EntityType
	leafActions    []types.EntityUID
	groupActions   []types.EntityUID
	actionEntities types.EntityMap
	requestEnvs    []RequestEnv
	prIndex        map[principalResourceKey][]types.EntityUID
}

type principalResourceKey struct {
	PrincipalType types.EntityType
	ResourceType  types.EntityType
}

// NewFromCedar parses a Cedar human-readable schema and eagerly resolves
// all type references. The returned Schema is immutable.
func NewFromCedar(filename string, src []byte) (*Schema, error) {
	a, err := parser.ParseSchema(filename, src)
	if err != nil {
		return nil, fmt.Errorf("parsing cedar schema: %w", err)
	}
	return newFromAST(a)
}

// NewFromJSON parses a Cedar JSON schema and eagerly resolves all type
// references. Supports both the namespaced format and the flat format
// ({"entityTypes":..., "actions":...} at top level).
func NewFromJSON(src []byte) (*Schema, error) {
	a, err := unmarshalJSONSchema(src)
	if err != nil {
		return nil, fmt.Errorf("parsing JSON schema: %w", err)
	}
	return newFromAST(a)
}

// NewSchemaFromAST creates a Schema from a pre-built AST.
// The AST is resolved eagerly; an error is returned if resolution fails.
func NewSchemaFromAST(in *ast.Schema) (*Schema, error) {
	return newFromAST(in)
}

// MarshalCedar encodes the schema in the human-readable Cedar format.
func (s *Schema) MarshalCedar() ([]byte, error) {
	return parser.MarshalSchema(s.astOrEmpty()), nil
}

// MarshalJSON encodes the schema in the Cedar JSON format.
func (s *Schema) MarshalJSON() ([]byte, error) {
	js := (*schemajson.Schema)(s.astOrEmpty())
	return js.MarshalJSON()
}

// AST returns the underlying AST. The returned value must not be mutated.
func (s *Schema) AST() *ast.Schema {
	return s.astOrEmpty()
}

// Resolve returns the resolved schema. Since the Schema is eagerly resolved
// during construction, this simply re-resolves from the AST.
func (s *Schema) Resolve() (*resolved.Schema, error) {
	return resolved.Resolve(s.astOrEmpty())
}

func (s *Schema) astOrEmpty() *ast.Schema {
	if s.inner == nil {
		return &ast.Schema{}
	}
	return s.inner
}

func newFromAST(a *ast.Schema) (*Schema, error) {
	rs, err := resolved.Resolve(a)
	if err != nil {
		return nil, err
	}
	s := &Schema{inner: a}
	s.buildFromResolved(rs)
	return s, nil
}

// unmarshalJSONSchema parses a JSON schema, handling both the standard
// namespaced format and the flat format (bare top-level entityTypes/actions).
func unmarshalJSONSchema(src []byte) (*ast.Schema, error) {
	// Peek at the top-level keys to detect the flat format.
	// Flat format has "entityTypes" and/or "actions" at top level;
	// standard format has namespace names (arbitrary strings) as keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(src, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	_, hasET := raw["entityTypes"]
	_, hasAct := raw["actions"]
	if hasET || hasAct {
		// Flat format: wrap under the empty namespace key.
		wrapped := map[string]json.RawMessage{"": src}
		wrappedBytes, err := json.Marshal(wrapped)
		if err != nil {
			return nil, err
		}
		var js schemajson.Schema
		if err := js.UnmarshalJSON(wrappedBytes); err != nil {
			return nil, fmt.Errorf("parsing flat JSON schema: %w", err)
		}
		a := ast.Schema(js)
		return &a, nil
	}

	// Standard namespaced format.
	var js schemajson.Schema
	if err := js.UnmarshalJSON(src); err != nil {
		return nil, fmt.Errorf("parsing JSON schema: %w", err)
	}
	a := ast.Schema(js)
	return &a, nil
}
