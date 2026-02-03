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
	Context   *jsonType       `json:"context,omitempty"`
	MemberOf  []jsonActionRef `json:"memberOf,omitempty"`
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
// Supports both namespace-based format (map[string]*jsonNamespace) and flat format.
func (v *Validator) parseSchemaJSON(data []byte) error {
	// First try namespace-based format
	var namespaces map[string]*jsonNamespace
	if err := json.Unmarshal(data, &namespaces); err != nil {
		return fmt.Errorf("failed to parse schema JSON: %w", err)
	}

	// Check if this looks like a namespace-based schema or flat schema
	// A flat schema has keys like "entityTypes" and "actions" at the top level
	// which would be parsed as namespace names
	if v.looksLikeFlatSchema(namespaces) {
		return v.parseFlatSchemaJSON(data)
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

// looksLikeFlatSchema detects if the parsed namespaces are actually a flat schema.
// In flat format, "entityTypes" and "actions" appear as namespace names.
func (v *Validator) looksLikeFlatSchema(namespaces map[string]*jsonNamespace) bool {
	_, hasEntityTypes := namespaces["entityTypes"]
	_, hasActions := namespaces["actions"]
	return hasEntityTypes || hasActions
}

// parseFlatSchemaJSON parses a flat schema format where entityTypes and actions
// are at the top level (not wrapped in a namespace).
func (v *Validator) parseFlatSchemaJSON(data []byte) error {
	var flat jsonNamespace
	if err := json.Unmarshal(data, &flat); err != nil {
		return fmt.Errorf("failed to parse flat schema JSON: %w", err)
	}

	return v.parseNamespace("", &flat)
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
		info, err := v.parseEntityType(fullName, &et)
		if err != nil {
			return err
		}
		v.entityTypes[types.EntityType(fullName)] = info
	}
	return nil
}

// parseEntityType processes a single entity type.
func (v *Validator) parseEntityType(fullName string, et *jsonEntityType) (*EntityTypeInfo, error) {
	info := &EntityTypeInfo{
		Attributes:    make(map[string]AttributeType),
		MemberOfTypes: make([]types.EntityType, 0, len(et.MemberOfTypes)),
	}

	if err := v.parseEntityShape(info, fullName, et.Shape); err != nil {
		return nil, err
	}

	for _, mot := range et.MemberOfTypes {
		info.MemberOfTypes = append(info.MemberOfTypes, types.EntityType(mot))
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

	if err := v.parseActionContext(info, nsName, name, act.Context); err != nil {
		return nil, err
	}

	v.parseActionMemberOf(info, nsName, act.MemberOf)

	return info, nil
}

// parseAppliesTo processes the appliesTo section of an action.
func (v *Validator) parseAppliesTo(info *ActionTypeInfo, nsName, actionName string, appliesTo *jsonAppliesTo) error {
	if appliesTo == nil {
		return nil
	}

	for _, pt := range appliesTo.PrincipalTypes {
		info.PrincipalTypes = append(info.PrincipalTypes, types.EntityType(pt))
	}

	for _, rt := range appliesTo.ResourceTypes {
		info.ResourceTypes = append(info.ResourceTypes, types.EntityType(rt))
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

// parseActionContext processes the top-level context of an action.
func (v *Validator) parseActionContext(info *ActionTypeInfo, nsName, actionName string, context *jsonType) error {
	if context == nil {
		return nil
	}

	ctx, err := v.parseRecordTypeWithOpen(context)
	if err != nil {
		return fmt.Errorf("failed to parse action %s context: %w", actionName, err)
	}
	// Merge with existing context (from appliesTo)
	for attrName, at := range ctx.Attributes {
		info.Context.Attributes[attrName] = at
	}
	return nil
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
func (v *Validator) parseTypeReference(typeName string) (CedarType, error) {
	if ct, ok := v.commonTypes[typeName]; ok {
		return ct, nil
	}
	if typeName != "" {
		return EntityType{Name: types.EntityType(typeName)}, nil
	}
	return UnknownType{}, nil
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
