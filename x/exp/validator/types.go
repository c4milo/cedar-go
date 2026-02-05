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

import "github.com/cedar-policy/cedar-go/types"

// CedarType represents a Cedar type for validation.
type CedarType interface {
	isCedarType()
	String() string
	// Type predicate methods for cleaner type checks
	IsBoolean() bool
	IsLong() bool
	IsString() bool
	IsEntity() bool
	IsSet() bool
	IsRecord() bool
	IsUnknown() bool
}

// Primitive types
type (
	BoolType   struct{}
	LongType   struct{}
	StringType struct{}
)

func (BoolType) isCedarType()   {}
func (LongType) isCedarType()   {}
func (StringType) isCedarType() {}

func (BoolType) String() string   { return "Bool" }
func (LongType) String() string   { return "Long" }
func (StringType) String() string { return "String" }

// Type predicates for BoolType
func (BoolType) IsBoolean() bool { return true }
func (BoolType) IsLong() bool    { return false }
func (BoolType) IsString() bool  { return false }
func (BoolType) IsEntity() bool  { return false }
func (BoolType) IsSet() bool     { return false }
func (BoolType) IsRecord() bool  { return false }
func (BoolType) IsUnknown() bool { return false }

// Type predicates for LongType
func (LongType) IsBoolean() bool { return false }
func (LongType) IsLong() bool    { return true }
func (LongType) IsString() bool  { return false }
func (LongType) IsEntity() bool  { return false }
func (LongType) IsSet() bool     { return false }
func (LongType) IsRecord() bool  { return false }
func (LongType) IsUnknown() bool { return false }

// Type predicates for StringType
func (StringType) IsBoolean() bool { return false }
func (StringType) IsLong() bool    { return false }
func (StringType) IsString() bool  { return true }
func (StringType) IsEntity() bool  { return false }
func (StringType) IsSet() bool     { return false }
func (StringType) IsRecord() bool  { return false }
func (StringType) IsUnknown() bool { return false }

// EntityType represents an entity type reference.
type EntityType struct {
	Name types.EntityType
}

func (EntityType) isCedarType() {}
func (e EntityType) String() string {
	return "Entity<" + string(e.Name) + ">"
}

// Type predicates for EntityType
func (EntityType) IsBoolean() bool { return false }
func (EntityType) IsLong() bool    { return false }
func (EntityType) IsString() bool  { return false }
func (EntityType) IsEntity() bool  { return true }
func (EntityType) IsSet() bool     { return false }
func (EntityType) IsRecord() bool  { return false }
func (EntityType) IsUnknown() bool { return false }

// SetType represents a set of elements of a given type.
type SetType struct {
	Element CedarType
}

func (SetType) isCedarType() {}
func (s SetType) String() string {
	return "Set<" + s.Element.String() + ">"
}

// Type predicates for SetType
func (SetType) IsBoolean() bool { return false }
func (SetType) IsLong() bool    { return false }
func (SetType) IsString() bool  { return false }
func (SetType) IsEntity() bool  { return false }
func (SetType) IsSet() bool     { return true }
func (SetType) IsRecord() bool  { return false }
func (SetType) IsUnknown() bool { return false }

// RecordType represents a record with typed attributes.
type RecordType struct {
	Attributes map[string]AttributeType
	// OpenRecord allows additional attributes not in schema
	OpenRecord bool
}

func (RecordType) isCedarType() {}
func (r RecordType) String() string {
	return "Record"
}

// Type predicates for RecordType
func (RecordType) IsBoolean() bool { return false }
func (RecordType) IsLong() bool    { return false }
func (RecordType) IsString() bool  { return false }
func (RecordType) IsEntity() bool  { return false }
func (RecordType) IsSet() bool     { return false }
func (RecordType) IsRecord() bool  { return true }
func (RecordType) IsUnknown() bool { return false }

// AttributeType represents a typed attribute, which may be required or optional.
type AttributeType struct {
	Type     CedarType
	Required bool
}

// ExtensionType represents Cedar extension types.
type ExtensionType struct {
	Name string // "decimal", "ipaddr", "datetime", "duration"
}

func (ExtensionType) isCedarType() {}
func (e ExtensionType) String() string {
	return e.Name
}

// Type predicates for ExtensionType
func (ExtensionType) IsBoolean() bool { return false }
func (ExtensionType) IsLong() bool    { return false }
func (ExtensionType) IsString() bool  { return false }
func (ExtensionType) IsEntity() bool  { return false }
func (ExtensionType) IsSet() bool     { return false }
func (ExtensionType) IsRecord() bool  { return false }
func (ExtensionType) IsUnknown() bool { return false }

// AnyEntityType matches any entity type.
type AnyEntityType struct{}

func (AnyEntityType) isCedarType()   {}
func (AnyEntityType) String() string { return "Entity" }

// Type predicates for AnyEntityType
func (AnyEntityType) IsBoolean() bool { return false }
func (AnyEntityType) IsLong() bool    { return false }
func (AnyEntityType) IsString() bool  { return false }
func (AnyEntityType) IsEntity() bool  { return true }
func (AnyEntityType) IsSet() bool     { return false }
func (AnyEntityType) IsRecord() bool  { return false }
func (AnyEntityType) IsUnknown() bool { return false }

// UnknownType represents an unknown or undeterminable type.
// This is used when the type cannot be determined due to missing context
// (e.g., action scope is 'all' so context type is unknown).
// Unknown types are treated leniently in type checking.
type UnknownType struct{}

func (UnknownType) isCedarType()   {}
func (UnknownType) String() string { return "Unknown" }

// Type predicates for UnknownType
func (UnknownType) IsBoolean() bool { return false }
func (UnknownType) IsLong() bool    { return false }
func (UnknownType) IsString() bool  { return false }
func (UnknownType) IsEntity() bool  { return false }
func (UnknownType) IsSet() bool     { return false }
func (UnknownType) IsRecord() bool  { return false }
func (UnknownType) IsUnknown() bool { return true }

// UnspecifiedType represents an attribute whose type was not specified in the schema.
// This is different from UnknownType - it indicates a schema that is malformed or incomplete.
// Using an UnspecifiedType attribute in a context that requires a specific type (like boolean
// conditions) is a validation error. However, comparisons involving UnspecifiedType are allowed
// (the comparison itself returns Bool).
type UnspecifiedType struct{}

func (UnspecifiedType) isCedarType()   {}
func (UnspecifiedType) String() string { return "Unspecified" }

// Type predicates for UnspecifiedType
func (UnspecifiedType) IsBoolean() bool { return false }
func (UnspecifiedType) IsLong() bool    { return false }
func (UnspecifiedType) IsString() bool  { return false }
func (UnspecifiedType) IsEntity() bool  { return false }
func (UnspecifiedType) IsSet() bool     { return false }
func (UnspecifiedType) IsRecord() bool  { return false }
func (UnspecifiedType) IsUnknown() bool { return true } // Treated as unknown for type checking

// TypesMatch checks if actual type is compatible with expected type.
func TypesMatch(expected, actual CedarType) bool {
	switch e := expected.(type) {
	case BoolType:
		_, ok := actual.(BoolType)
		return ok
	case LongType:
		_, ok := actual.(LongType)
		return ok
	case StringType:
		_, ok := actual.(StringType)
		return ok
	case EntityType:
		return matchEntityType(e, actual)
	case AnyEntityType:
		return matchAnyEntityType(actual)
	case SetType:
		return matchSetType(e, actual)
	case RecordType:
		return matchRecordType(e, actual)
	case ExtensionType:
		return matchExtensionType(e, actual)
	case UnknownType:
		return true // Unknown matches anything
	default:
		return false
	}
}

// matchEntityType checks if actual matches a specific entity type.
func matchEntityType(expected EntityType, actual CedarType) bool {
	a, ok := actual.(EntityType)
	if !ok {
		_, ok = actual.(AnyEntityType)
		return ok
	}
	return expected.Name == a.Name
}

// matchAnyEntityType checks if actual is any entity type.
func matchAnyEntityType(actual CedarType) bool {
	switch actual.(type) {
	case EntityType, AnyEntityType:
		return true
	default:
		return false
	}
}

// matchSetType checks if actual matches a set type.
func matchSetType(expected SetType, actual CedarType) bool {
	a, ok := actual.(SetType)
	if !ok {
		return false
	}
	return TypesMatch(expected.Element, a.Element)
}

// matchRecordType checks if actual matches a record type.
func matchRecordType(expected RecordType, actual CedarType) bool {
	a, ok := actual.(RecordType)
	if !ok {
		return false
	}
	return recordAttributesMatch(expected.Attributes, a.Attributes)
}

// recordAttributesMatch checks that expected attributes match actual attributes.
func recordAttributesMatch(expected, actual map[string]AttributeType) bool {
	for name, attr := range expected {
		aAttr, exists := actual[name]
		if !exists {
			if attr.Required {
				return false
			}
			continue
		}
		if !TypesMatch(attr.Type, aAttr.Type) {
			return false
		}
	}
	return true
}

// matchExtensionType checks if actual matches an extension type.
func matchExtensionType(expected ExtensionType, actual CedarType) bool {
	a, ok := actual.(ExtensionType)
	if !ok {
		return false
	}
	return expected.Name == a.Name
}
