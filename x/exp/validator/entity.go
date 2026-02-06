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
	"fmt"

	"github.com/cedar-policy/cedar-go/types"
)

// validateEntity validates a single entity.
func (v *Validator) validateEntity(uid types.EntityUID, entity types.Entity) []EntityError {
	entityInfo, ok := v.entityTypes[uid.Type]
	if !ok {
		return v.handleUnknownEntityType(uid)
	}

	var errs []EntityError
	errs = append(errs, v.validateEntityAttributes(uid, entity, entityInfo)...)
	errs = append(errs, v.validateUndeclaredAttributes(uid, entity, entityInfo)...)
	errs = append(errs, v.validateParentRelationships(uid, entity, entityInfo)...)
	return errs
}

// handleUnknownEntityType handles validation when entity type is not in schema.
func (v *Validator) handleUnknownEntityType(uid types.EntityUID) []EntityError {
	if v.isActionEntityType(uid.Type) {
		return nil // Action entities are handled differently
	}
	return []EntityError{{
		EntityUID: uid,
		Message:   fmt.Sprintf("entity type %s is not defined in schema", uid.Type),
	}}
}

// validateEntityAttributes validates all declared attributes of an entity.
func (v *Validator) validateEntityAttributes(uid types.EntityUID, entity types.Entity, info *EntityTypeInfo) []EntityError {
	var errs []EntityError
	for attrName, attrType := range info.Attributes {
		if err := v.validateEntityAttribute(uid, entity, attrName, attrType); err != nil {
			errs = append(errs, *err)
		}
	}
	return errs
}

// validateEntityAttribute validates a single attribute of an entity.
func (v *Validator) validateEntityAttribute(uid types.EntityUID, entity types.Entity, attrName string, attrType AttributeType) *EntityError {
	attrVal, exists := entity.Attributes.Get(types.String(attrName))
	if !exists {
		if attrType.Required {
			return &EntityError{EntityUID: uid, Message: fmt.Sprintf("required attribute %s is missing", attrName)}
		}
		return nil
	}
	if err := v.validateValue(attrVal, attrType.Type); err != nil {
		return &EntityError{EntityUID: uid, Message: fmt.Sprintf("attribute %s: %v", attrName, err)}
	}
	return nil
}

// validateUndeclaredAttributes checks for undeclared attributes in strict mode.
func (v *Validator) validateUndeclaredAttributes(uid types.EntityUID, entity types.Entity, info *EntityTypeInfo) []EntityError {
	if !v.strictEntityValidation || info.OpenRecord {
		return nil
	}
	var errs []EntityError
	for attrName := range entity.Attributes.All() {
		if _, declared := info.Attributes[string(attrName)]; !declared {
			errs = append(errs, EntityError{
				EntityUID: uid,
				Message:   fmt.Sprintf("attribute %s is not declared in schema", attrName),
			})
		}
	}
	return errs
}

// validateParentRelationships validates that parent relationships are allowed.
func (v *Validator) validateParentRelationships(uid types.EntityUID, entity types.Entity, info *EntityTypeInfo) []EntityError {
	var errs []EntityError
	for parent := range entity.Parents.All() {
		if !v.typeInList(parent.Type, info.MemberOfTypes) {
			errs = append(errs, EntityError{
				EntityUID: uid,
				Message:   fmt.Sprintf("entity cannot be member of type %s", parent.Type),
			})
		}
	}
	return errs
}

// validateContext validates context against an expected record type.
func (v *Validator) validateContext(context types.Value, expected RecordType) error {
	rec, ok := context.(types.Record)
	if !ok {
		return fmt.Errorf("context must be a record, got %T", context)
	}

	if err := v.validateContextAttributes(rec, expected); err != nil {
		return err
	}
	return v.validateContextUndeclaredAttributes(rec, expected)
}

// validateContextAttributes validates all declared context attributes.
func (v *Validator) validateContextAttributes(rec types.Record, expected RecordType) error {
	for attrName, attrType := range expected.Attributes {
		if err := v.validateContextAttribute(rec, attrName, attrType); err != nil {
			return err
		}
	}
	return nil
}

// validateContextAttribute validates a single context attribute.
func (v *Validator) validateContextAttribute(rec types.Record, attrName string, attrType AttributeType) error {
	val, exists := rec.Get(types.String(attrName))
	if !exists {
		if attrType.Required {
			return fmt.Errorf("required context attribute %s is missing", attrName)
		}
		return nil
	}
	if err := v.validateValue(val, attrType.Type); err != nil {
		return fmt.Errorf("context attribute %s: %v", attrName, err)
	}
	return nil
}

// validateContextUndeclaredAttributes checks for undeclared context attributes in strict mode.
func (v *Validator) validateContextUndeclaredAttributes(rec types.Record, expected RecordType) error {
	if !v.strictEntityValidation || expected.OpenRecord {
		return nil
	}
	for attrName := range rec.All() {
		if _, declared := expected.Attributes[string(attrName)]; !declared {
			return fmt.Errorf("context attribute %s is not declared in schema", attrName)
		}
	}
	return nil
}

// validateValue validates a value against an expected type.
func (v *Validator) validateValue(val types.Value, expected CedarType) error {
	actual := v.inferType(val)
	if !TypesMatch(expected, actual) {
		return fmt.Errorf("expected %s, got %s", expected, actual)
	}
	return nil
}

// inferType infers the Cedar type from a value.
func (v *Validator) inferType(val types.Value) CedarType {
	switch typedVal := val.(type) {
	case types.Boolean:
		return BoolType{}
	case types.Long:
		return LongType{}
	case types.String:
		return StringType{}
	case types.EntityUID:
		return EntityType{Name: typedVal.Type}
	case types.Set:
		return v.inferSetType(typedVal)
	case types.Record:
		return v.inferRecordType(typedVal)
	case types.Decimal:
		return ExtensionType{Name: "decimal"}
	case types.IPAddr:
		return ExtensionType{Name: "ipaddr"}
	case types.Datetime:
		return ExtensionType{Name: "datetime"}
	case types.Duration:
		return ExtensionType{Name: "duration"}
	default:
		return UnknownType{}
	}
}

// inferSetType infers the type of a Set value.
func (v *Validator) inferSetType(s types.Set) CedarType {
	if s.Len() == 0 {
		return SetType{Element: UnknownType{}}
	}
	// Infer element type from first element
	for elem := range s.All() {
		return SetType{Element: v.inferType(elem)}
	}
	return SetType{Element: UnknownType{}}
}

// inferRecordType infers the type of a Record value.
func (v *Validator) inferRecordType(r types.Record) CedarType {
	attrs := make(map[string]AttributeType)
	for k, rv := range r.All() {
		attrs[string(k)] = AttributeType{Type: v.inferType(rv), Required: true}
	}
	return RecordType{Attributes: attrs}
}
