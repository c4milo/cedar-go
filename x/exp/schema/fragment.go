package schema

import (
	"fmt"
	"maps"

	"github.com/cedar-policy/cedar-go/x/exp/schema/ast"
	schemajson "github.com/cedar-policy/cedar-go/x/exp/schema/internal/json"
	"github.com/cedar-policy/cedar-go/x/exp/schema/internal/parser"
)

// SchemaFragment is an unresolved schema fragment that can be merged with
// other fragments before resolution. Unlike Schema, a fragment may contain
// forward references that won't resolve until all fragments are combined.
type SchemaFragment struct {
	inner *ast.Schema
}

// NewFragmentFromCedar parses a Cedar human-readable schema fragment.
func NewFragmentFromCedar(filename string, src []byte) (*SchemaFragment, error) {
	a, err := parser.ParseSchema(filename, src)
	if err != nil {
		return nil, fmt.Errorf("parsing cedar schema fragment: %w", err)
	}
	return &SchemaFragment{inner: a}, nil
}

// NewFragmentFromJSON parses a Cedar JSON schema fragment.
// Supports both namespaced and flat formats.
func NewFragmentFromJSON(src []byte) (*SchemaFragment, error) {
	a, err := unmarshalJSONSchema(src)
	if err != nil {
		return nil, fmt.Errorf("parsing JSON schema fragment: %w", err)
	}
	return &SchemaFragment{inner: a}, nil
}

// Merge combines two fragments, returning a new fragment. Returns an error
// if any entity type, action, or common type is declared in both fragments
// within the same namespace.
func (f *SchemaFragment) Merge(other *SchemaFragment) (*SchemaFragment, error) {
	merged := &ast.Schema{
		Entities:    make(ast.Entities, len(f.inner.Entities)),
		Enums:       make(ast.Enums, len(f.inner.Enums)),
		Actions:     make(ast.Actions, len(f.inner.Actions)),
		CommonTypes: make(ast.CommonTypes, len(f.inner.CommonTypes)),
		Namespaces:  make(ast.Namespaces),
	}

	// Copy base entities, enums, actions, common types
	copyEntities(merged.Entities, f.inner.Entities)
	copyEnums(merged.Enums, f.inner.Enums)
	copyActions(merged.Actions, f.inner.Actions)
	copyCommonTypes(merged.CommonTypes, f.inner.CommonTypes)

	// Merge other's bare declarations
	if err := mergeEntities(merged.Entities, other.inner.Entities, ""); err != nil {
		return nil, err
	}
	if err := mergeEnums(merged.Enums, other.inner.Enums, ""); err != nil {
		return nil, err
	}
	if err := mergeActions(merged.Actions, other.inner.Actions, ""); err != nil {
		return nil, err
	}
	if err := mergeCommonTypes(merged.CommonTypes, other.inner.CommonTypes, ""); err != nil {
		return nil, err
	}

	// Copy base namespaces
	for ns, base := range f.inner.Namespaces {
		merged.Namespaces[ns] = copyNamespace(base)
	}

	// Merge other's namespaces
	for ns, other := range other.inner.Namespaces {
		existing, ok := merged.Namespaces[ns]
		if !ok {
			merged.Namespaces[ns] = copyNamespace(other)
			continue
		}
		nsStr := string(ns)
		if err := mergeEntities(existing.Entities, other.Entities, nsStr); err != nil {
			return nil, err
		}
		if err := mergeEnums(existing.Enums, other.Enums, nsStr); err != nil {
			return nil, err
		}
		if err := mergeActions(existing.Actions, other.Actions, nsStr); err != nil {
			return nil, err
		}
		if err := mergeCommonTypes(existing.CommonTypes, other.CommonTypes, nsStr); err != nil {
			return nil, err
		}
		merged.Namespaces[ns] = existing
	}

	return &SchemaFragment{inner: merged}, nil
}

// FromFragments merges all fragments and resolves the combined schema.
func FromFragments(fragments ...*SchemaFragment) (*Schema, error) {
	if len(fragments) == 0 {
		return newFromAST(&ast.Schema{})
	}
	result := fragments[0]
	for _, f := range fragments[1:] {
		var err error
		result, err = result.Merge(f)
		if err != nil {
			return nil, err
		}
	}
	return newFromAST(result.inner)
}

// MarshalCedar encodes the fragment in the human-readable Cedar format.
func (f *SchemaFragment) MarshalCedar() ([]byte, error) {
	return parser.MarshalSchema(f.inner), nil
}

// MarshalJSON encodes the fragment in the Cedar JSON format.
func (f *SchemaFragment) MarshalJSON() ([]byte, error) {
	js := (*schemajson.Schema)(f.inner)
	return js.MarshalJSON()
}

// merge helpers

func copyEntities(dst, src ast.Entities) {
	maps.Copy(dst, src)
}

func copyEnums(dst, src ast.Enums) {
	maps.Copy(dst, src)
}

func copyActions(dst, src ast.Actions) {
	maps.Copy(dst, src)
}

func copyCommonTypes(dst, src ast.CommonTypes) {
	maps.Copy(dst, src)
}

func copyNamespace(ns ast.Namespace) ast.Namespace {
	result := ast.Namespace{
		Annotations: ns.Annotations,
		Entities:    make(ast.Entities, len(ns.Entities)),
		Enums:       make(ast.Enums, len(ns.Enums)),
		Actions:     make(ast.Actions, len(ns.Actions)),
		CommonTypes: make(ast.CommonTypes, len(ns.CommonTypes)),
	}
	copyEntities(result.Entities, ns.Entities)
	copyEnums(result.Enums, ns.Enums)
	copyActions(result.Actions, ns.Actions)
	copyCommonTypes(result.CommonTypes, ns.CommonTypes)
	return result
}

func mergeEntities(dst, src ast.Entities, ns string) error {
	for k, v := range src {
		if _, exists := dst[k]; exists {
			return fmt.Errorf("duplicate entity type %q in namespace %q", k, ns)
		}
		dst[k] = v
	}
	return nil
}

func mergeEnums(dst, src ast.Enums, ns string) error {
	for k, v := range src {
		if _, exists := dst[k]; exists {
			return fmt.Errorf("duplicate enum type %q in namespace %q", k, ns)
		}
		dst[k] = v
	}
	return nil
}

func mergeActions(dst, src ast.Actions, ns string) error {
	for k, v := range src {
		if _, exists := dst[k]; exists {
			return fmt.Errorf("duplicate action %q in namespace %q", k, ns)
		}
		dst[k] = v
	}
	return nil
}

func mergeCommonTypes(dst, src ast.CommonTypes, ns string) error {
	for k, v := range src {
		if _, exists := dst[k]; exists {
			return fmt.Errorf("duplicate common type %q in namespace %q", k, ns)
		}
		dst[k] = v
	}
	return nil
}

// qualifyName produces a fully-qualified name.
func qualifyName(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return namespace + "::" + name
}
