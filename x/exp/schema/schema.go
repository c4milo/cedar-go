package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"strings"

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
// Returns an error if the schema syntax is invalid.
//
// Note: This performs lenient parsing. Schema well-formedness validation
// (cycles, duplicates, etc.) is performed when creating a Validator.
//
// Any errors returned will have file positions matching filename.
func NewFromCedar(filename string, src []byte) (*Schema, error) {
	humanSchema, err := parser.ParseFile(filename, src)
	if err != nil {
		return nil, err
	}
	jsonSchema := ast.ConvertHuman2JSON(humanSchema)

	// Validate identifiers (though Cedar parser should already enforce this)
	if err := validateIdentifiers(jsonSchema); err != nil {
		return nil, err
	}

	return &Schema{
		jsonSchema: jsonSchema,
	}, nil
}

// NewFromJSON parses the JSON schema from src and returns a Schema.
// Returns an error if the JSON syntax is invalid.
//
// Supports both namespace format ({"ns": {"entityTypes": {...}}}) and
// flat format ({"entityTypes": {...}, "actions": {...}}).
//
// Note: This performs lenient parsing. Schema well-formedness validation
// (cycles, duplicates, etc.) is performed when creating a Validator.
func NewFromJSON(src []byte) (*Schema, error) {
	// First, try to detect if this is a flat schema or namespace schema
	// by checking the top-level keys
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(src, &raw); err != nil {
		return nil, err
	}

	// Check if this looks like a flat schema (has entityTypes/actions/commonTypes at top level)
	_, hasEntityTypes := raw["entityTypes"]
	_, hasActions := raw["actions"]
	_, hasCommonTypes := raw["commonTypes"]

	if hasEntityTypes || hasActions || hasCommonTypes {
		// This is a flat schema - parse it as a single anonymous namespace
		var flatSchema ast.JSONNamespace
		if err := json.Unmarshal(src, &flatSchema); err != nil {
			return nil, err
		}
		// Convert to namespace format with empty namespace name
		jsonSchema := ast.JSONSchema{
			"": &flatSchema,
		}

		// Validate identifiers early to catch invalid names
		if err := validateIdentifiers(jsonSchema); err != nil {
			return nil, err
		}

		return &Schema{
			jsonSchema: jsonSchema,
		}, nil
	}

	// This is a namespace-based schema
	var jsonSchema ast.JSONSchema
	if err := json.Unmarshal(src, &jsonSchema); err != nil {
		return nil, err
	}

	// Validate identifiers early to catch invalid names
	if err := validateIdentifiers(jsonSchema); err != nil {
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

// SchemaFragment represents a partial schema that may reference
// types not declared within it. Fragments can be combined into
// a complete Schema using FromFragments().
//
// SchemaFragment is immutable after construction and safe for concurrent use.
type SchemaFragment struct {
	jsonSchema ast.JSONSchema
}

// NewFragmentFromCedar parses the human-readable schema from src and returns a SchemaFragment.
// The fragment may reference types not declared within it.
// Returns an error if the schema syntax is invalid.
//
// Any errors returned will have file positions matching filename.
func NewFragmentFromCedar(filename string, src []byte) (*SchemaFragment, error) {
	humanSchema, err := parser.ParseFile(filename, src)
	if err != nil {
		return nil, err
	}
	jsonSchema := ast.ConvertHuman2JSON(humanSchema)

	// Validate identifiers (though Cedar parser should already enforce this)
	if err := validateIdentifiers(jsonSchema); err != nil {
		return nil, err
	}

	return &SchemaFragment{
		jsonSchema: jsonSchema,
	}, nil
}

// NewFragmentFromJSON parses the JSON schema from src and returns a SchemaFragment.
// The fragment may reference types not declared within it.
// Returns an error if the JSON syntax is invalid.
//
// Supports both namespace format ({"ns": {"entityTypes": {...}}}) and
// flat format ({"entityTypes": {...}, "actions": {...}}).
func NewFragmentFromJSON(src []byte) (*SchemaFragment, error) {
	// First, try to detect if this is a flat schema or namespace schema
	// by checking the top-level keys
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(src, &raw); err != nil {
		return nil, err
	}

	// Check if this looks like a flat schema (has entityTypes/actions/commonTypes at top level)
	_, hasEntityTypes := raw["entityTypes"]
	_, hasActions := raw["actions"]
	_, hasCommonTypes := raw["commonTypes"]

	if hasEntityTypes || hasActions || hasCommonTypes {
		// This is a flat schema - parse it as a single anonymous namespace
		var flatSchema ast.JSONNamespace
		if err := json.Unmarshal(src, &flatSchema); err != nil {
			return nil, err
		}
		// Convert to namespace format with empty namespace name
		jsonSchema := ast.JSONSchema{
			"": &flatSchema,
		}

		// Validate identifiers early to catch invalid names
		if err := validateIdentifiers(jsonSchema); err != nil {
			return nil, err
		}

		return &SchemaFragment{
			jsonSchema: jsonSchema,
		}, nil
	}

	// This is a namespace-based schema
	var jsonSchema ast.JSONSchema
	if err := json.Unmarshal(src, &jsonSchema); err != nil {
		return nil, err
	}

	// Validate identifiers early to catch invalid names
	if err := validateIdentifiers(jsonSchema); err != nil {
		return nil, err
	}

	return &SchemaFragment{
		jsonSchema: jsonSchema,
	}, nil
}

// MarshalCedar serializes the fragment into the human readable format.
func (f *SchemaFragment) MarshalCedar() ([]byte, error) {
	if f.jsonSchema == nil {
		return nil, fmt.Errorf("fragment is empty")
	}
	humanSchema := ast.ConvertJSON2Human(f.jsonSchema)
	var buf bytes.Buffer
	err := ast.Format(humanSchema, &buf)
	return buf.Bytes(), err
}

// MarshalJSON serializes the fragment into the JSON format.
func (f *SchemaFragment) MarshalJSON() ([]byte, error) {
	if f.jsonSchema == nil {
		return nil, nil
	}
	return json.Marshal(f.jsonSchema)
}

// Merge combines this fragment with another, returning a new fragment.
// Returns an error if both fragments define the same type in the same namespace.
// Does not validate completeness - use FromFragments for validation.
func (f *SchemaFragment) Merge(other *SchemaFragment) (*SchemaFragment, error) {
	if base := handleNilMerge(f, other); base != nil {
		return base, nil
	}

	merged := copyJSONSchema(f.jsonSchema)
	if err := mergeSchemaInto(merged, other.jsonSchema); err != nil {
		return nil, err
	}
	return &SchemaFragment{jsonSchema: merged}, nil
}

// handleNilMerge handles the case where one or both fragments are nil.
// Returns a non-nil result if the nil case was handled, nil otherwise.
func handleNilMerge(f, other *SchemaFragment) *SchemaFragment {
	if f == nil || f.jsonSchema == nil {
		if other == nil {
			return &SchemaFragment{jsonSchema: make(ast.JSONSchema)}
		}
		return &SchemaFragment{jsonSchema: copyJSONSchema(other.jsonSchema)}
	}
	if other == nil || other.jsonSchema == nil {
		return &SchemaFragment{jsonSchema: copyJSONSchema(f.jsonSchema)}
	}
	return nil
}

// mergeSchemaInto merges the source schema into the destination.
func mergeSchemaInto(dst, src ast.JSONSchema) error {
	for nsName, srcNs := range src {
		if srcNs == nil {
			continue
		}
		existingNs, exists := dst[nsName]
		if !exists {
			dst[nsName] = copyJSONNamespace(srcNs)
			continue
		}
		mergedNs, err := mergeNamespaces(existingNs, srcNs, nsName)
		if err != nil {
			return err
		}
		dst[nsName] = mergedNs
	}
	return nil
}

// FromFragments combines multiple schema fragments into a complete Schema.
// Returns an error if:
// - Two fragments define the same type in the same namespace
// - Any fragment references a type not defined in any fragment
func FromFragments(fragments ...*SchemaFragment) (*Schema, error) {
	if len(fragments) == 0 {
		return &Schema{jsonSchema: make(ast.JSONSchema)}, nil
	}

	// Merge all fragments
	var merged *SchemaFragment
	var err error
	for i, frag := range fragments {
		if i == 0 {
			merged = frag
			continue
		}
		merged, err = merged.Merge(frag)
		if err != nil {
			return nil, err
		}
	}

	if merged == nil || merged.jsonSchema == nil {
		return &Schema{jsonSchema: make(ast.JSONSchema)}, nil
	}

	// Validate all identifiers
	if err := validateIdentifiers(merged.jsonSchema); err != nil {
		return nil, err
	}

	// Validate all type references
	if err := validateReferences(merged.jsonSchema); err != nil {
		return nil, err
	}

	return &Schema{jsonSchema: merged.jsonSchema}, nil
}

// mergeNamespaces merges two JSON namespaces, detecting conflicts.
func mergeNamespaces(a, b *ast.JSONNamespace, nsName string) (*ast.JSONNamespace, error) {
	result := &ast.JSONNamespace{
		EntityTypes: make(map[string]*ast.JSONEntity),
		Actions:     make(map[string]*ast.JSONAction),
		CommonTypes: make(map[string]*ast.JSONCommonType),
		Annotations: make(map[string]string),
	}

	// Copy from a
	maps.Copy(result.EntityTypes, a.EntityTypes)
	maps.Copy(result.Actions, a.Actions)
	maps.Copy(result.CommonTypes, a.CommonTypes)
	maps.Copy(result.Annotations, a.Annotations)

	// Merge from b, checking for conflicts
	for name := range b.EntityTypes {
		if _, exists := result.EntityTypes[name]; exists {
			return nil, fmt.Errorf("duplicate entity type %q in namespace %q", name, nsName)
		}
		result.EntityTypes[name] = b.EntityTypes[name]
	}
	for name := range b.Actions {
		if _, exists := result.Actions[name]; exists {
			return nil, fmt.Errorf("duplicate action %q in namespace %q", name, nsName)
		}
		result.Actions[name] = b.Actions[name]
	}
	for name := range b.CommonTypes {
		if _, exists := result.CommonTypes[name]; exists {
			return nil, fmt.Errorf("duplicate common type %q in namespace %q", name, nsName)
		}
		result.CommonTypes[name] = b.CommonTypes[name]
	}
	maps.Copy(result.Annotations, b.Annotations)

	return result, nil
}

// copyJSONSchema creates a shallow copy of a JSONSchema.
func copyJSONSchema(src ast.JSONSchema) ast.JSONSchema {
	if src == nil {
		return nil
	}
	result := make(ast.JSONSchema)
	for k, v := range src {
		result[k] = copyJSONNamespace(v)
	}
	return result
}

// copyJSONNamespace creates a shallow copy of a JSONNamespace.
func copyJSONNamespace(src *ast.JSONNamespace) *ast.JSONNamespace {
	if src == nil {
		return nil
	}
	result := &ast.JSONNamespace{
		EntityTypes: make(map[string]*ast.JSONEntity),
		Actions:     make(map[string]*ast.JSONAction),
		CommonTypes: make(map[string]*ast.JSONCommonType),
		Annotations: make(map[string]string),
	}
	maps.Copy(result.EntityTypes, src.EntityTypes)
	maps.Copy(result.Actions, src.Actions)
	maps.Copy(result.CommonTypes, src.CommonTypes)
	maps.Copy(result.Annotations, src.Annotations)
	return result
}

// validateReferences checks that all type references in the schema resolve to defined types.
func validateReferences(schema ast.JSONSchema) error {
	definedTypes := collectDefinedTypes(schema)
	var errors []string

	for nsName, ns := range schema {
		if ns == nil {
			continue
		}
		errors = append(errors, validateEntityTypeReferences(ns.EntityTypes, nsName, definedTypes)...)
		errors = append(errors, validateActionTypeReferences(ns.Actions, nsName, definedTypes)...)
		errors = append(errors, validateCommonTypeRefs(ns.CommonTypes, nsName, definedTypes)...)
	}

	if len(errors) > 0 {
		return fmt.Errorf("unresolved type references:\n  %s", strings.Join(errors, "\n  "))
	}
	return nil
}

// collectDefinedTypes builds a map of all defined types in the schema.
func collectDefinedTypes(schema ast.JSONSchema) map[string]bool {
	definedTypes := make(map[string]bool)
	for nsName, ns := range schema {
		if ns == nil {
			continue
		}
		for entityName := range ns.EntityTypes {
			definedTypes[qualifyName(nsName, entityName)] = true
		}
		for commonName := range ns.CommonTypes {
			definedTypes[qualifyName(nsName, commonName)] = true
		}
	}
	return definedTypes
}

// validateEntityTypeReferences validates references within entity type definitions.
func validateEntityTypeReferences(entities map[string]*ast.JSONEntity, nsName string, definedTypes map[string]bool) []string {
	var errors []string
	for entityName, entity := range entities {
		if entity == nil {
			continue
		}
		errors = append(errors, validateEntityMemberOf(entityName, entity.MemberOfTypes, nsName, definedTypes)...)
		errors = append(errors, validateEntityShapeAndTags(entityName, entity, nsName, definedTypes)...)
	}
	return errors
}

// validateEntityMemberOf validates memberOfTypes references for an entity.
func validateEntityMemberOf(entityName string, memberOfTypes []string, nsName string, definedTypes map[string]bool) []string {
	var errors []string
	fqn := qualifyName(nsName, entityName)
	for _, memberOf := range memberOfTypes {
		if !isDefinedType(memberOf, nsName, definedTypes) {
			errors = append(errors, fmt.Sprintf("entity %q references undefined type %q", fqn, memberOf))
		}
	}
	return errors
}

// validateEntityShapeAndTags validates shape and tags references for an entity.
func validateEntityShapeAndTags(entityName string, entity *ast.JSONEntity, nsName string, definedTypes map[string]bool) []string {
	var errors []string
	fqn := qualifyName(nsName, entityName)
	if entity.Shape != nil {
		errors = append(errors, validateTypeReferences(entity.Shape, nsName, definedTypes, fmt.Sprintf("entity %q shape", fqn))...)
	}
	if entity.Tags != nil {
		errors = append(errors, validateTypeReferences(entity.Tags, nsName, definedTypes, fmt.Sprintf("entity %q tags", fqn))...)
	}
	return errors
}

// validateActionTypeReferences validates references within action definitions.
func validateActionTypeReferences(actions map[string]*ast.JSONAction, nsName string, definedTypes map[string]bool) []string {
	var errors []string
	for actionName, action := range actions {
		if action == nil || action.AppliesTo == nil {
			continue
		}
		errors = append(errors, validateActionAppliesTo(actionName, action.AppliesTo, nsName, definedTypes)...)
	}
	return errors
}

// validateActionAppliesTo validates appliesTo references for an action.
func validateActionAppliesTo(actionName string, appliesTo *ast.JSONAppliesTo, nsName string, definedTypes map[string]bool) []string {
	var errors []string
	fqn := qualifyName(nsName, actionName)

	for _, pt := range appliesTo.PrincipalTypes {
		if !isDefinedType(pt, nsName, definedTypes) {
			errors = append(errors, fmt.Sprintf("action %q references undefined principal type %q", fqn, pt))
		}
	}
	for _, rt := range appliesTo.ResourceTypes {
		if !isDefinedType(rt, nsName, definedTypes) {
			errors = append(errors, fmt.Sprintf("action %q references undefined resource type %q", fqn, rt))
		}
	}
	if appliesTo.Context != nil {
		errors = append(errors, validateTypeReferences(appliesTo.Context, nsName, definedTypes, fmt.Sprintf("action %q context", fqn))...)
	}
	return errors
}

// validateCommonTypeRefs validates references within common type definitions.
func validateCommonTypeRefs(commonTypes map[string]*ast.JSONCommonType, nsName string, definedTypes map[string]bool) []string {
	var errors []string
	for typeName, commonType := range commonTypes {
		if commonType == nil || commonType.JSONType == nil {
			continue
		}
		fqn := qualifyName(nsName, typeName)
		errors = append(errors, validateTypeReferences(commonType.JSONType, nsName, definedTypes, fmt.Sprintf("common type %q", fqn))...)
	}
	return errors
}

// validateTypeReferences checks type references within a JSONType.
func validateTypeReferences(t *ast.JSONType, currentNs string, definedTypes map[string]bool, context string) []string {
	if t == nil {
		return nil
	}

	switch t.Type {
	case "Entity", "EntityOrCommon":
		return validateEntityTypeRef(t, currentNs, definedTypes, context)
	case "Set":
		return validateSetTypeRef(t, currentNs, definedTypes, context)
	case "Record":
		return validateRecordTypeRef(t, currentNs, definedTypes, context)
	default:
		return validateDefaultTypeRef(t, currentNs, definedTypes, context)
	}
}

// validateEntityTypeRef validates an Entity or EntityOrCommon type reference.
func validateEntityTypeRef(t *ast.JSONType, currentNs string, definedTypes map[string]bool, context string) []string {
	if t.Name != "" && !isDefinedType(t.Name, currentNs, definedTypes) {
		return []string{fmt.Sprintf("%s references undefined type %q", context, t.Name)}
	}
	return nil
}

// validateSetTypeRef validates a Set type reference by checking its element type.
func validateSetTypeRef(t *ast.JSONType, currentNs string, definedTypes map[string]bool, context string) []string {
	if t.Element != nil {
		return validateTypeReferences(t.Element, currentNs, definedTypes, context)
	}
	return nil
}

// validateRecordTypeRef validates a Record type reference by checking all attribute types.
func validateRecordTypeRef(t *ast.JSONType, currentNs string, definedTypes map[string]bool, context string) []string {
	var errors []string
	for attrName, attr := range t.Attributes {
		if attr == nil {
			continue
		}
		attrType := &ast.JSONType{
			Type:       attr.Type,
			Element:    attr.Element,
			Name:       attr.Name,
			Attributes: attr.Attributes,
		}
		errors = append(errors, validateTypeReferences(attrType, currentNs, definedTypes, fmt.Sprintf("%s attribute %q", context, attrName))...)
	}
	return errors
}

// validateDefaultTypeRef validates type references by name (e.g., common types).
func validateDefaultTypeRef(t *ast.JSONType, currentNs string, definedTypes map[string]bool, context string) []string {
	if t.Name != "" && !isDefinedType(t.Name, currentNs, definedTypes) && !isPrimitiveType(t.Type) {
		return []string{fmt.Sprintf("%s references undefined type %q", context, t.Name)}
	}
	return nil
}

// isDefinedType checks if a type reference resolves to a defined type.
func isDefinedType(typeName, currentNs string, definedTypes map[string]bool) bool {
	// Primitive types are always valid
	if isPrimitiveType(typeName) {
		return true
	}

	// Check if it's a fully qualified name
	if definedTypes[typeName] {
		return true
	}

	// Try qualifying with current namespace
	fqn := qualifyName(currentNs, typeName)
	if definedTypes[fqn] {
		return true
	}

	// Try the empty namespace
	fqnEmpty := qualifyName("", typeName)
	return definedTypes[fqnEmpty]
}

// isPrimitiveType returns true for Cedar primitive types.
func isPrimitiveType(typeName string) bool {
	switch typeName {
	case "String", "Long", "Bool", "Boolean", "Record", "Set", "Extension", "Entity", "EntityOrCommon":
		return true
	default:
		return false
	}
}

// qualifyName returns a fully qualified type name.
func qualifyName(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return namespace + "::" + name
}

// isValidCedarIdent checks if a string is a valid Cedar identifier.
// Cedar identifiers must start with a letter or underscore, followed by
// letters, digits, or underscores.
func isValidCedarIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if !isValidIdentRune(r, i == 0) {
			return false
		}
	}
	return true
}

// isValidIdentRune checks if a rune is valid in a Cedar identifier.
func isValidIdentRune(r rune, first bool) bool {
	isLetter := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
	isUnderscore := r == '_'
	if first {
		return isLetter || isUnderscore
	}
	isDigit := r >= '0' && r <= '9'
	return isLetter || isUnderscore || isDigit
}

// validateIdentifiers checks that all identifiers in the schema are valid Cedar identifiers.
// Note: Only entity type names, common type names, and namespace names must be valid identifiers.
// Record attribute names can be arbitrary strings (they're quoted in Cedar syntax).
// Action names are also arbitrary strings.
func validateIdentifiers(schema ast.JSONSchema) error {
	var errors []string

	for nsName, ns := range schema {
		if ns == nil {
			continue
		}
		errors = append(errors, validateNamespaceIdentifiers(nsName, ns)...)
	}

	if len(errors) > 0 {
		return fmt.Errorf("invalid identifiers:\n  %s", strings.Join(errors, "\n  "))
	}
	return nil
}

// validateNamespaceIdentifiers validates all identifiers within a single namespace.
func validateNamespaceIdentifiers(nsName string, ns *ast.JSONNamespace) []string {
	var errors []string

	// Validate namespace name parts
	errors = append(errors, validateNamespaceName(nsName)...)

	// Validate entity type names
	errors = append(errors, validateEntityTypeNames(nsName, ns.EntityTypes)...)

	// Validate common type names
	errors = append(errors, validateCommonTypeNames(nsName, ns.CommonTypes)...)

	// Validate type references in shapes and contexts
	errors = append(errors, validateEntityShapeReferences(nsName, ns.EntityTypes)...)
	errors = append(errors, validateActionContextReferences(nsName, ns.Actions)...)
	errors = append(errors, validateCommonTypeReferences(nsName, ns.CommonTypes)...)

	return errors
}

// validateNamespaceName validates namespace name parts.
func validateNamespaceName(nsName string) []string {
	if nsName == "" {
		return nil
	}
	var errors []string
	for _, part := range strings.Split(nsName, "::") {
		if !isValidCedarIdent(part) {
			errors = append(errors, fmt.Sprintf("invalid namespace identifier %q in %q", part, nsName))
		}
	}
	return errors
}

// validateEntityTypeNames validates entity type names.
func validateEntityTypeNames(nsName string, types map[string]*ast.JSONEntity) []string {
	var errors []string
	for name := range types {
		if !isValidCedarIdent(name) {
			errors = append(errors, fmt.Sprintf("invalid entity type identifier %q in namespace %q", name, nsName))
		}
	}
	return errors
}

// validateCommonTypeNames validates common type names.
func validateCommonTypeNames(nsName string, types map[string]*ast.JSONCommonType) []string {
	var errors []string
	for name := range types {
		if !isValidCedarIdent(name) {
			errors = append(errors, fmt.Sprintf("invalid common type identifier %q in namespace %q", name, nsName))
		}
	}
	return errors
}

// validateEntityShapeReferences validates type references in entity shapes.
func validateEntityShapeReferences(nsName string, types map[string]*ast.JSONEntity) []string {
	var errors []string
	for name, entity := range types {
		if entity != nil && entity.Shape != nil {
			errors = append(errors, validateTypeReferencesOnly(entity.Shape, nsName, fmt.Sprintf("entity %q shape", name))...)
		}
	}
	return errors
}

// validateActionContextReferences validates type references in action contexts.
func validateActionContextReferences(nsName string, actions map[string]*ast.JSONAction) []string {
	var errors []string
	for name, action := range actions {
		if action != nil && action.AppliesTo != nil && action.AppliesTo.Context != nil {
			errors = append(errors, validateTypeReferencesOnly(action.AppliesTo.Context, nsName, fmt.Sprintf("action %q context", name))...)
		}
	}
	return errors
}

// validateCommonTypeReferences validates type references in common types.
func validateCommonTypeReferences(nsName string, types map[string]*ast.JSONCommonType) []string {
	var errors []string
	for name, ct := range types {
		if ct != nil && ct.JSONType != nil {
			errors = append(errors, validateTypeReferencesOnly(ct.JSONType, nsName, fmt.Sprintf("common type %q", name))...)
		}
	}
	return errors
}

// validateTypeReferencesOnly checks that type references (EntityOrCommon) within a JSONType
// have valid identifiers. It does NOT validate attribute names (which can be any string).
func validateTypeReferencesOnly(t *ast.JSONType, currentNs string, context string) []string {
	if t == nil {
		return nil
	}

	switch t.Type {
	case "Record":
		return validateRecordTypeReferences(t, currentNs, context)
	case "Set":
		return validateSetTypeReferences(t, currentNs, context)
	case "EntityOrCommon":
		return validateEntityOrCommonReference(t, context)
	}
	return nil
}

// validateRecordTypeReferences validates type references in record attributes.
func validateRecordTypeReferences(t *ast.JSONType, currentNs string, context string) []string {
	var errors []string
	for attrName, attr := range t.Attributes {
		if attr == nil {
			continue
		}
		attrType := &ast.JSONType{
			Type:       attr.Type,
			Element:    attr.Element,
			Name:       attr.Name,
			Attributes: attr.Attributes,
		}
		errors = append(errors, validateTypeReferencesOnly(attrType, currentNs, fmt.Sprintf("%s attribute %q", context, attrName))...)
	}
	return errors
}

// validateSetTypeReferences validates type references in set elements.
func validateSetTypeReferences(t *ast.JSONType, currentNs string, context string) []string {
	if t.Element == nil {
		return nil
	}
	return validateTypeReferencesOnly(t.Element, currentNs, context)
}

// validateEntityOrCommonReference validates entity/common type name parts.
func validateEntityOrCommonReference(t *ast.JSONType, context string) []string {
	if t.Name == "" {
		return nil
	}
	var errors []string
	for _, part := range strings.Split(t.Name, "::") {
		if !isValidCedarIdent(part) {
			errors = append(errors, fmt.Sprintf("%s references type with invalid identifier %q", context, part))
		}
	}
	return errors
}
