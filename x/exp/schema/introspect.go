package schema

import (
	"iter"

	"github.com/cedar-policy/cedar-go/types"
)

// EntityTypes returns an iterator over all entity types declared in the schema.
// O(n) in the number of entity types.
func (s *Schema) EntityTypes() iter.Seq[types.EntityType] {
	return func(yield func(types.EntityType) bool) {
		for et := range s.entityTypes {
			if !yield(et) {
				return
			}
		}
	}
}

// Actions returns an iterator over all leaf actions (those with appliesTo) in the schema.
// O(n) in the number of leaf actions. Precomputed during construction.
func (s *Schema) Actions() iter.Seq[types.EntityUID] {
	return func(yield func(types.EntityUID) bool) {
		for _, uid := range s.leafActions {
			if !yield(uid) {
				return
			}
		}
	}
}

// ActionGroups returns an iterator over all action groups (those without appliesTo) in the schema.
// O(n) in the number of action groups. Precomputed during construction.
func (s *Schema) ActionGroups() iter.Seq[types.EntityUID] {
	return func(yield func(types.EntityUID) bool) {
		for _, uid := range s.groupActions {
			if !yield(uid) {
				return
			}
		}
	}
}

// Principals returns a deduplicated iterator over all entity types that appear
// as principal types in any action's appliesTo.
// O(n) in the number of unique principal types. Precomputed during construction.
func (s *Schema) Principals() iter.Seq[types.EntityType] {
	return func(yield func(types.EntityType) bool) {
		for _, pt := range s.principals {
			if !yield(pt) {
				return
			}
		}
	}
}

// Resources returns a deduplicated iterator over all entity types that appear
// as resource types in any action's appliesTo.
// O(n) in the number of unique resource types. Precomputed during construction.
func (s *Schema) Resources() iter.Seq[types.EntityType] {
	return func(yield func(types.EntityType) bool) {
		for _, rt := range s.resources {
			if !yield(rt) {
				return
			}
		}
	}
}

// PrincipalsForAction returns the principal types allowed for a given action.
// O(n) in the number of principal types for this action.
// The second return value is false if the action is not found in the schema.
func (s *Schema) PrincipalsForAction(action types.EntityUID) (iter.Seq[types.EntityType], bool) {
	info, ok := s.actionTypes[action]
	if !ok {
		return nil, false
	}
	return func(yield func(types.EntityType) bool) {
		for _, pt := range info.PrincipalTypes {
			if !yield(pt) {
				return
			}
		}
	}, true
}

// ResourcesForAction returns the resource types allowed for a given action.
// O(n) in the number of resource types for this action.
// The second return value is false if the action is not found in the schema.
func (s *Schema) ResourcesForAction(action types.EntityUID) (iter.Seq[types.EntityType], bool) {
	info, ok := s.actionTypes[action]
	if !ok {
		return nil, false
	}
	return func(yield func(types.EntityType) bool) {
		for _, rt := range info.ResourceTypes {
			if !yield(rt) {
				return
			}
		}
	}, true
}

// ActionsForPrincipalAndResource returns actions applicable to the given
// principal type and resource type combination.
// O(n) in the number of matching actions. Uses a precomputed reverse index.
func (s *Schema) ActionsForPrincipalAndResource(principalType types.EntityType, resourceType types.EntityType) iter.Seq[types.EntityUID] {
	actions := s.prIndex[principalResourceKey{PrincipalType: principalType, ResourceType: resourceType}]
	return func(yield func(types.EntityUID) bool) {
		for _, uid := range actions {
			if !yield(uid) {
				return
			}
		}
	}
}

// Ancestors returns the entity types that the given entity type can be a member of.
// O(n) in the number of ancestor types.
// The second return value is false if the entity type is not found in the schema.
func (s *Schema) Ancestors(entityType types.EntityType) (iter.Seq[types.EntityType], bool) {
	info, ok := s.entityTypes[entityType]
	if !ok {
		return nil, false
	}
	return func(yield func(types.EntityType) bool) {
		for _, mot := range info.MemberOfTypes {
			if !yield(mot) {
				return
			}
		}
	}, true
}

// ActionEntities returns the action hierarchy as an EntityMap.
// Each action is an entity whose parents are its MemberOf targets.
// Returns the precomputed map — callers must not mutate it.
func (s *Schema) ActionEntities() types.EntityMap {
	return s.actionEntities
}

// RequestEnvs returns an iterator over all valid request environments.
// Each entry is a (principalType, action, resourceType) triple.
// O(n) in the number of environments. Precomputed during construction.
func (s *Schema) RequestEnvs() iter.Seq[RequestEnv] {
	return func(yield func(RequestEnv) bool) {
		for _, env := range s.requestEnvs {
			if !yield(env) {
				return
			}
		}
	}
}

// ActionInfo returns the schema information for a given action.
// O(1) map lookup. Returns nil, false if the action is not found.
func (s *Schema) ActionInfo(action types.EntityUID) (*ActionTypeInfo, bool) {
	info, ok := s.actionTypes[action]
	return info, ok
}

// EntityTypeInfoFor returns the schema information for a given entity type.
// O(1) map lookup. Returns nil, false if the entity type is not found.
func (s *Schema) EntityTypeInfoFor(entityType types.EntityType) (*EntityTypeInfo, bool) {
	info, ok := s.entityTypes[entityType]
	return info, ok
}

// EntityTypesMap returns the underlying entity types map.
// Intended for use by the validator package. Callers must not mutate the returned map.
func (s *Schema) EntityTypesMap() map[types.EntityType]*EntityTypeInfo {
	return s.entityTypes
}

// ActionTypesMap returns the underlying action types map.
// Intended for use by the validator package. Callers must not mutate the returned map.
func (s *Schema) ActionTypesMap() map[types.EntityUID]*ActionTypeInfo {
	return s.actionTypes
}

// CommonTypesMap returns the underlying common types map.
// Intended for use by the validator package. Callers must not mutate the returned map.
func (s *Schema) CommonTypesMap() map[string]CedarType {
	return s.commonTypes
}
