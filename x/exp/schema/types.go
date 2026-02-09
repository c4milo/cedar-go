package schema

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

// EntityCedarType represents an entity type reference.
type EntityCedarType struct {
	Name types.EntityType
}

func (EntityCedarType) isCedarType() {}
func (e EntityCedarType) String() string {
	return "Entity<" + string(e.Name) + ">"
}

// Type predicates for EntityCedarType
func (EntityCedarType) IsBoolean() bool { return false }
func (EntityCedarType) IsLong() bool    { return false }
func (EntityCedarType) IsString() bool  { return false }
func (EntityCedarType) IsEntity() bool  { return true }
func (EntityCedarType) IsSet() bool     { return false }
func (EntityCedarType) IsRecord() bool  { return false }
func (EntityCedarType) IsUnknown() bool { return false }

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
func (RecordType) String() string {
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

// EntityTypeInfo contains schema information about an entity type.
type EntityTypeInfo struct {
	// Attributes defined on this entity type
	Attributes map[string]AttributeType
	// Types this entity can be a member of
	MemberOfTypes []types.EntityType
	// OpenRecord when true allows additional attributes not declared in schema
	OpenRecord bool
}

// ActionTypeInfo contains schema information about an action.
type ActionTypeInfo struct {
	// Principal types this action applies to
	PrincipalTypes []types.EntityType
	// Resource types this action applies to
	ResourceTypes []types.EntityType
	// Context type for this action
	Context RecordType
	// Actions this action is a member of
	MemberOf []types.EntityUID
}

// RequestEnv represents a valid principal-type / action / resource-type
// combination per the schema's appliesTo declarations.
type RequestEnv struct {
	PrincipalType types.EntityType
	Action        types.EntityUID
	ResourceType  types.EntityType
}

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
	case EntityCedarType:
		return matchEntityCedarType(e, actual)
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

func matchEntityCedarType(expected EntityCedarType, actual CedarType) bool {
	a, ok := actual.(EntityCedarType)
	if !ok {
		_, ok = actual.(AnyEntityType)
		return ok
	}
	return expected.Name == a.Name
}

func matchAnyEntityType(actual CedarType) bool {
	switch actual.(type) {
	case EntityCedarType, AnyEntityType:
		return true
	default:
		return false
	}
}

func matchSetType(expected SetType, actual CedarType) bool {
	a, ok := actual.(SetType)
	if !ok {
		return false
	}
	return TypesMatch(expected.Element, a.Element)
}

func matchRecordType(expected RecordType, actual CedarType) bool {
	a, ok := actual.(RecordType)
	if !ok {
		return false
	}
	for name, attr := range expected.Attributes {
		aAttr, exists := a.Attributes[name]
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

func matchExtensionType(expected ExtensionType, actual CedarType) bool {
	a, ok := actual.(ExtensionType)
	if !ok {
		return false
	}
	return expected.Name == a.Name
}
