// Copyright Cedar Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package validator

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cedar-policy/cedar-go/types"
)

// jsonNamespace represents a namespace in the Cedar JSON schema format.
type jsonNamespace struct {
	EntityTypes map[string]jsonEntityType `json:"entityTypes"`
	Actions     map[string]jsonAction     `json:"actions"`
	CommonTypes map[string]jsonType       `json:"commonTypes,omitempty"`
}

type jsonEntityType struct {
	Shape         *jsonType `json:"shape,omitempty"`
	MemberOfTypes []string  `json:"memberOfTypes,omitempty"`
}

type jsonAction struct {
	AppliesTo *jsonAppliesTo  `json:"appliesTo,omitempty"`
	MemberOf  []jsonActionRef `json:"memberOf,omitempty"`
	Context   *jsonType       `json:"context,omitempty"` // Context can be at action level or inside appliesTo
}

type jsonAppliesTo struct {
	PrincipalTypes []string  `json:"principalTypes,omitempty"`
	ResourceTypes  []string  `json:"resourceTypes,omitempty"`
	Context        *jsonType `json:"context,omitempty"`
}

type jsonActionRef struct {
	Type string `json:"type,omitempty"`
	ID   string `json:"id"`
}

type jsonType struct {
	Type       string              `json:"type"`
	Element    *jsonType           `json:"element,omitempty"`
	Attributes map[string]jsonAttr `json:"attributes,omitempty"`
	Name       string              `json:"name,omitempty"`
}

type jsonAttr struct {
	Type       string              `json:"type,omitempty"`
	Element    *jsonType           `json:"element,omitempty"`
	Required   *bool               `json:"required,omitempty"`
	Name       string              `json:"name,omitempty"`
	Attributes map[string]jsonAttr `json:"attributes,omitempty"`
}

// parseSchemaJSON parses the JSON schema into type information.
// The schema package normalizes all schema formats to namespace-based format,
// so we only need to handle that format here.
func (v *Validator) parseSchemaJSON(data []byte) error {
	var namespaces map[string]*jsonNamespace
	if err := json.Unmarshal(data, &namespaces); err != nil {
		return fmt.Errorf("failed to parse schema JSON: %w", err)
	}

	// Process namespace-based schema
	for nsName, ns := range namespaces {
		if ns == nil {
			continue
		}
		if err := v.parseNamespace(nsName, ns); err != nil {
			return err
		}
	}

	return nil
}

// parseNamespace processes a single namespace from the schema.
func (v *Validator) parseNamespace(nsName string, ns *jsonNamespace) error {
	if err := v.parseCommonTypes(nsName, ns.CommonTypes); err != nil {
		return err
	}
	if err := v.parseEntityTypes(nsName, ns.EntityTypes); err != nil {
		return err
	}
	return v.parseActions(nsName, ns.Actions)
}

// parseCommonTypes processes common type definitions.
func (v *Validator) parseCommonTypes(nsName string, commonTypes map[string]jsonType) error {
	for name, jt := range commonTypes {
		fullName := qualifiedName(nsName, name)
		ct, err := v.parseJSONType(&jt)
		if err != nil {
			return fmt.Errorf("failed to parse common type %s: %w", fullName, err)
		}
		v.commonTypes[fullName] = ct
	}
	return nil
}

// parseEntityTypes processes entity type definitions.
func (v *Validator) parseEntityTypes(nsName string, entityTypes map[string]jsonEntityType) error {
	for name, et := range entityTypes {
		fullName := qualifiedName(nsName, name)
		info, err := v.parseEntityType(nsName, fullName, &et)
		if err != nil {
			return err
		}
		v.entityTypes[types.EntityType(fullName)] = info
	}
	return nil
}

// parseEntityType processes a single entity type.
func (v *Validator) parseEntityType(nsName, fullName string, et *jsonEntityType) (*EntityTypeInfo, error) {
	info := &EntityTypeInfo{
		Attributes:    make(map[string]AttributeType),
		MemberOfTypes: make([]types.EntityType, 0, len(et.MemberOfTypes)),
	}

	if err := v.parseEntityShape(info, fullName, et.Shape); err != nil {
		return nil, err
	}

	// Qualify and deduplicate memberOfTypes using a set (Cedar Rust deduplicates these)
	seen := make(map[types.EntityType]struct{})
	for _, mot := range et.MemberOfTypes {
		et := types.EntityType(qualifyTypeName(nsName, mot))
		if _, exists := seen[et]; !exists {
			info.MemberOfTypes = append(info.MemberOfTypes, et)
			seen[et] = struct{}{}
		}
	}

	return info, nil
}

// parseEntityShape processes the shape (attributes) of an entity type.
func (v *Validator) parseEntityShape(info *EntityTypeInfo, entityName string, shape *jsonType) error {
	if shape == nil {
		// No shape means open record (no attributes defined, any attributes allowed)
		info.OpenRecord = true
		return nil
	}

	if shape.Attributes != nil {
		for attrName, attr := range shape.Attributes {
			at, err := v.parseJSONAttr(&attr)
			if err != nil {
				return fmt.Errorf("failed to parse attribute %s.%s: %w", entityName, attrName, err)
			}
			info.Attributes[attrName] = at
		}
	}

	// Entities with a defined shape are closed (no extra attributes in strict mode)
	info.OpenRecord = false
	return nil
}

// parseActions processes action definitions.
func (v *Validator) parseActions(nsName string, actions map[string]jsonAction) error {
	for name, act := range actions {
		info, err := v.parseAction(nsName, name, &act)
		if err != nil {
			return err
		}
		// Use qualified action type for namespaced actions
		actionType := qualifiedName(nsName, "Action")
		actionUID := types.EntityUID{Type: types.EntityType(actionType), ID: types.String(name)}
		v.actionTypes[actionUID] = info
	}
	return nil
}

// parseAction processes a single action definition.
func (v *Validator) parseAction(nsName, name string, act *jsonAction) (*ActionTypeInfo, error) {
	info := &ActionTypeInfo{
		PrincipalTypes: make([]types.EntityType, 0),
		ResourceTypes:  make([]types.EntityType, 0),
		Context:        RecordType{Attributes: make(map[string]AttributeType)},
		MemberOf:       make([]types.EntityUID, 0),
	}

	if err := v.parseAppliesTo(info, nsName, name, act.AppliesTo); err != nil {
		return nil, err
	}

	// Context can be defined at the action level or inside appliesTo.
	// Action-level context takes precedence if both are specified.
	if act.Context != nil {
		ctx, err := v.parseRecordTypeWithOpen(act.Context)
		if err != nil {
			return nil, fmt.Errorf("failed to parse action %s context: %w", name, err)
		}
		info.Context = ctx
	}

	v.parseActionMemberOf(info, nsName, act.MemberOf)

	return info, nil
}

// parseAppliesTo processes the appliesTo section of an action.
func (v *Validator) parseAppliesTo(info *ActionTypeInfo, nsName, actionName string, appliesTo *jsonAppliesTo) error {
	if appliesTo == nil {
		return nil
	}

	// Qualify and deduplicate principal types using a set (Cedar Rust deduplicates these)
	seenPrincipal := make(map[types.EntityType]struct{})
	for _, pt := range appliesTo.PrincipalTypes {
		et := types.EntityType(qualifyTypeName(nsName, pt))
		if _, exists := seenPrincipal[et]; !exists {
			info.PrincipalTypes = append(info.PrincipalTypes, et)
			seenPrincipal[et] = struct{}{}
		}
	}

	// Qualify and deduplicate resource types using a set
	seenResource := make(map[types.EntityType]struct{})
	for _, rt := range appliesTo.ResourceTypes {
		et := types.EntityType(qualifyTypeName(nsName, rt))
		if _, exists := seenResource[et]; !exists {
			info.ResourceTypes = append(info.ResourceTypes, et)
			seenResource[et] = struct{}{}
		}
	}

	if appliesTo.Context != nil {
		ctx, err := v.parseRecordTypeWithOpen(appliesTo.Context)
		if err != nil {
			return fmt.Errorf("failed to parse action %s context: %w", actionName, err)
		}
		info.Context = ctx
	}

	return nil
}

// qualifyTypeName adds the namespace prefix to a type name if it doesn't already have one.
// Type names that already contain "::" are considered fully qualified.
func qualifyTypeName(namespace, typeName string) string {
	if namespace == "" || strings.Contains(typeName, "::") {
		return typeName
	}
	return namespace + "::" + typeName
}

// parseActionMemberOf processes the memberOf section of an action.
func (v *Validator) parseActionMemberOf(info *ActionTypeInfo, nsName string, memberOf []jsonActionRef) {
	for _, mo := range memberOf {
		typ := qualifiedName(nsName, "Action")
		if mo.Type != "" {
			typ = mo.Type
		}
		info.MemberOf = append(info.MemberOf, types.EntityUID{
			Type: types.EntityType(typ),
			ID:   types.String(mo.ID),
		})
	}
}

// qualifiedName creates a fully-qualified name from namespace and local name.
func qualifiedName(namespace, localName string) string {
	if namespace == "" {
		return localName
	}
	return namespace + "::" + localName
}

// parseJSONType converts a JSON type definition to a CedarType.
func (v *Validator) parseJSONType(jt *jsonType) (CedarType, error) {
	if jt == nil {
		return RecordType{Attributes: make(map[string]AttributeType)}, nil
	}

	switch jt.Type {
	case "Boolean", "Bool":
		return BoolType{}, nil
	case "Long":
		return LongType{}, nil
	case "String":
		return StringType{}, nil
	case "Entity":
		return v.parseEntityRefType(jt.Name), nil
	case "Set":
		return v.parseSetType(jt.Element)
	case "Record":
		return v.parseRecordType(jt.Attributes)
	case "Extension":
		return v.parseExtensionType(jt.Name), nil
	default:
		return v.parseTypeReference(jt.Type)
	}
}

// parseEntityRefType creates an EntityType or AnyEntityType.
func (v *Validator) parseEntityRefType(name string) CedarType {
	if name != "" {
		return EntityType{Name: types.EntityType(name)}
	}
	return AnyEntityType{}
}

// parseSetType creates a SetType.
func (v *Validator) parseSetType(element *jsonType) (CedarType, error) {
	if element != nil {
		elem, err := v.parseJSONType(element)
		if err != nil {
			return nil, err
		}
		return SetType{Element: elem}, nil
	}
	return SetType{Element: UnknownType{}}, nil
}

// parseRecordType creates a RecordType.
func (v *Validator) parseRecordType(attributes map[string]jsonAttr) (CedarType, error) {
	rec := RecordType{Attributes: make(map[string]AttributeType)}
	for name, attr := range attributes {
		at, err := v.parseJSONAttr(&attr)
		if err != nil {
			return nil, err
		}
		rec.Attributes[name] = at
	}
	return rec, nil
}

// parseRecordTypeWithOpen creates a RecordType.
func (v *Validator) parseRecordTypeWithOpen(jt *jsonType) (RecordType, error) {
	rec := RecordType{Attributes: make(map[string]AttributeType)}
	if jt == nil {
		return rec, nil
	}
	for name, attr := range jt.Attributes {
		at, err := v.parseJSONAttr(&attr)
		if err != nil {
			return rec, err
		}
		rec.Attributes[name] = at
	}
	return rec, nil
}

// parseExtensionType creates an ExtensionType or UnknownType.
func (v *Validator) parseExtensionType(name string) CedarType {
	if name != "" {
		return ExtensionType{Name: name}
	}
	return UnknownType{}
}

// parseTypeReference handles common type or entity type references.
// For type references that cannot be resolved (not a common type and not a known
// entity type), returns UnknownType to allow graceful handling during type checking.
// This matches Lean's behavior where unknown type references don't cause hard failures.
func (v *Validator) parseTypeReference(typeName string) (CedarType, error) {
	if ct, ok := v.commonTypes[typeName]; ok {
		return ct, nil
	}
	// Check if this is a known entity type reference.
	// Note: Entity types may not all be parsed yet when this is called during
	// attribute parsing, so we need to be lenient here.
	if typeName != "" {
		// We return EntityType for valid-looking type names, but the type checker
		// will validate that the entity type actually exists when attributes are accessed.
		// For completely invalid type references (like numeric strings), we could
		// return UnknownType, but to maintain backward compatibility and allow
		// forward references, we return EntityType and let the type checker handle it.
		return EntityType{Name: types.EntityType(typeName)}, nil
	}
	// Empty type name means the type was not specified in the schema.
	// Return UnspecifiedType to mark this as a schema error that should be
	// caught when the attribute is used in a context requiring a specific type.
	return UnspecifiedType{}, nil
}

// parseJSONAttr converts a JSON attribute definition to an AttributeType.
func (v *Validator) parseJSONAttr(ja *jsonAttr) (AttributeType, error) {
	required := true
	if ja.Required != nil {
		required = *ja.Required
	}

	ct, err := v.parseAttrType(ja)
	if err != nil {
		return AttributeType{}, err
	}

	return AttributeType{Type: ct, Required: required}, nil
}

// parseAttrType parses the type portion of an attribute.
func (v *Validator) parseAttrType(ja *jsonAttr) (CedarType, error) {
	switch ja.Type {
	case "Boolean", "Bool":
		return BoolType{}, nil
	case "Long":
		return LongType{}, nil
	case "String":
		return StringType{}, nil
	case "Entity":
		return v.parseEntityRefType(ja.Name), nil
	case "Set":
		return v.parseSetType(ja.Element)
	case "Record":
		return v.parseRecordType(ja.Attributes)
	case "Extension":
		return v.parseExtensionType(ja.Name), nil
	default:
		return v.parseTypeReference(ja.Type)
	}
}
