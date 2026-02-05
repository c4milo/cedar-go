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

// Type checking helper functions and utilities.

// isTypeBoolean returns true if the type is BoolType.
func isTypeBoolean(t CedarType) bool {
	_, ok := t.(BoolType)
	return ok
}

// isTypeLong returns true if the type is LongType.
func isTypeLong(t CedarType) bool {
	_, ok := t.(LongType)
	return ok
}

// isTypeString returns true if the type is StringType.
func isTypeString(t CedarType) bool {
	_, ok := t.(StringType)
	return ok
}

// isTypeEntity returns true if the type is EntityType.
func isTypeEntity(t CedarType) bool {
	_, ok := t.(EntityType)
	return ok
}

// isTypeSet returns true if the type is SetType.
func isTypeSet(t CedarType) bool {
	_, ok := t.(SetType)
	return ok
}

// isTypeUnknown returns true if the type is UnknownType.
func isTypeUnknown(t CedarType) bool {
	_, ok := t.(UnknownType)
	return ok
}

// unifyTypes returns a type that represents both types.
// If either type is unknown, returns the other.
// If types match, returns the first.
// Otherwise returns UnknownType.
func unifyTypes(t1, t2 CedarType) CedarType {
	if isTypeUnknown(t1) {
		return t2
	}
	if isTypeUnknown(t2) {
		return t1
	}
	if TypesMatch(t1, t2) {
		return t1
	}
	return UnknownType{}
}

// typeCat represents a type category for comparison purposes.
// Types in the same category can be compared with == and !=.
type typeCat int

const (
	catUnknown typeCat = iota
	catBool
	catLong
	catString
	catEntity
	catSet
	catRecord
	catExtDecimal
	catExtIPAddr
	catExtDatetime
	catExtDuration
)

// typesAreComparable checks if two types can be compared with == or !=.
// Cedar's type system requires that equality operands have the same base type.
// However, if either type is unknown or unresolved, we allow the comparison
// to match Lean's lenient behavior.
func (ctx *typeContext) typesAreComparable(t1, t2 CedarType) bool {
	cat1 := ctx.typeCategory(t1)
	cat2 := ctx.typeCategory(t2)

	// If either type is unknown, comparisons are allowed (lenient)
	if cat1 == catUnknown || cat2 == catUnknown {
		return true
	}

	// Types are comparable if they're in the same category
	return cat1 == cat2
}

// typeCategory returns the category of a type for comparison purposes.
func (ctx *typeContext) typeCategory(t CedarType) typeCat {
	switch ct := t.(type) {
	case BoolType:
		return catBool
	case LongType:
		return catLong
	case StringType:
		return catString
	case EntityType:
		// Action entity types are special - they're in actionTypes, not entityTypes.
		// They are still entities and should be in the entity category.
		if ctx.v.isActionEntityType(ct.Name) {
			return catEntity
		}
		// Empty entity type (used for variables with unknown type) is still an entity.
		// This ensures that principal/resource/action variables are always entities.
		if ct.Name == "" {
			return catEntity
		}
		// For entity types that look like real entity types (defined in schema),
		// categorize as catEntity. This ensures comparing real entities to strings is an error.
		if _, ok := ctx.v.entityTypes[ct.Name]; ok {
			return catEntity
		}
		// Unknown entity types (including custom types from attributes) are treated
		// as unknown to allow lenient comparison with any type.
		return catUnknown
	case AnyEntityType:
		return catEntity
	case SetType:
		return catSet
	case RecordType:
		return catRecord
	case ExtensionType:
		switch ct.Name {
		case "decimal":
			return catExtDecimal
		case "ipaddr":
			return catExtIPAddr
		case "datetime":
			return catExtDatetime
		case "duration":
			return catExtDuration
		}
		return catUnknown
	case UnspecifiedType:
		// UnspecifiedType is treated as unknown for comparison purposes.
		// This allows comparisons with unspecified types (they return Bool),
		// while using unspecified types as conditions is caught separately.
		return catUnknown
	default:
		return catUnknown
	}
}
