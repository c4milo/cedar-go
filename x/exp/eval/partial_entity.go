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

package eval

import (
	"github.com/cedar-policy/cedar-go/types"
)

// PartialEntityUID represents an entity UID where the ID may be unknown.
// The entity type is always known, but the ID can be nil to indicate
// it's a variable that will be bound later during evaluation.
//
// This is useful for partial evaluation scenarios where you want to
// evaluate policies with an unknown principal or resource ID.
//
// Example:
//
//	// Known type, unknown ID
//	partial := NewPartialEntityUID("User", nil)
//
//	// Known type and ID (concrete)
//	concrete := PartialEntityUIDFromConcrete(types.NewEntityUID("User", "alice"))
type PartialEntityUID struct {
	// Type is the entity type (always known)
	Type types.EntityType
	// ID is the entity ID, or nil if unknown
	ID *types.String
}

// NewPartialEntityUID creates a new PartialEntityUID with the given type and optional ID.
// If id is nil, the entity ID is considered unknown/variable.
func NewPartialEntityUID(entityType types.EntityType, id *types.String) PartialEntityUID {
	return PartialEntityUID{
		Type: entityType,
		ID:   id,
	}
}

// PartialEntityUIDFromConcrete creates a PartialEntityUID from a concrete EntityUID.
func PartialEntityUIDFromConcrete(uid types.EntityUID) PartialEntityUID {
	id := uid.ID
	return PartialEntityUID{
		Type: uid.Type,
		ID:   &id,
	}
}

// IsKnown returns true if both the type and ID are known.
func (p PartialEntityUID) IsKnown() bool {
	return p.ID != nil
}

// ToEntityUID converts to a concrete EntityUID.
// Panics if the ID is unknown. Check IsKnown() first.
func (p PartialEntityUID) ToEntityUID() types.EntityUID {
	if p.ID == nil {
		panic("cannot convert partial entity UID with unknown ID to concrete EntityUID")
	}
	return types.EntityUID{
		Type: p.Type,
		ID:   *p.ID,
	}
}

// PartialEntity represents an entity where some attributes, ancestors, or tags
// may be unknown. This is useful for partial evaluation scenarios.
//
// Example:
//
//	// Entity with known UID but unknown attributes
//	partial := NewPartialEntity(
//	    types.NewEntityUID("User", "alice"),
//	    nil,  // unknown attributes
//	    nil,  // unknown ancestors
//	    nil,  // unknown tags
//	)
//
//	// Entity with known attributes
//	attrs := types.NewRecord(types.RecordMap{"name": types.String("Alice")})
//	partial := NewPartialEntity(
//	    types.NewEntityUID("User", "alice"),
//	    &attrs,
//	    nil,
//	    nil,
//	)
type PartialEntity struct {
	// UID is the entity's unique identifier (always known)
	UID types.EntityUID

	// Attributes contains the entity's attributes, or nil if unknown
	Attributes *types.Record

	// Ancestors contains the entity's parent entities, or nil if unknown
	Ancestors *types.EntityUIDSet

	// Tags contains the entity's tags, or nil if unknown
	Tags *types.Record
}

// NewPartialEntity creates a new PartialEntity.
// Any of attrs, ancestors, or tags can be nil to indicate they are unknown.
func NewPartialEntity(
	uid types.EntityUID,
	attrs *types.Record,
	ancestors *types.EntityUIDSet,
	tags *types.Record,
) PartialEntity {
	return PartialEntity{
		UID:        uid,
		Attributes: attrs,
		Ancestors:  ancestors,
		Tags:       tags,
	}
}

// PartialEntityFromConcrete creates a PartialEntity from a concrete Entity.
// All fields will be known (non-nil).
func PartialEntityFromConcrete(e types.Entity) PartialEntity {
	attrs := e.Attributes
	ancestors := e.Parents
	tags := e.Tags
	return PartialEntity{
		UID:        e.UID,
		Attributes: &attrs,
		Ancestors:  &ancestors,
		Tags:       &tags,
	}
}

// IsFullyKnown returns true if all fields (attributes, ancestors, tags) are known.
func (p PartialEntity) IsFullyKnown() bool {
	return p.Attributes != nil && p.Ancestors != nil && p.Tags != nil
}

// HasKnownAttributes returns true if the attributes are known.
func (p PartialEntity) HasKnownAttributes() bool {
	return p.Attributes != nil
}

// HasKnownAncestors returns true if the ancestors are known.
func (p PartialEntity) HasKnownAncestors() bool {
	return p.Ancestors != nil
}

// HasKnownTags returns true if the tags are known.
func (p PartialEntity) HasKnownTags() bool {
	return p.Tags != nil
}

// ToEntity converts to a concrete Entity.
// Unknown fields are replaced with empty values.
func (p PartialEntity) ToEntity() types.Entity {
	var attrs types.Record
	if p.Attributes != nil {
		attrs = *p.Attributes
	}

	var ancestors types.EntityUIDSet
	if p.Ancestors != nil {
		ancestors = *p.Ancestors
	} else {
		ancestors = types.NewEntityUIDSet()
	}

	var tags types.Record
	if p.Tags != nil {
		tags = *p.Tags
	}

	return types.Entity{
		UID:        p.UID,
		Attributes: attrs,
		Parents:    ancestors,
		Tags:       tags,
	}
}

// PartialEntities is a collection of PartialEntity values.
// It can be used to represent a set of entities where some
// entity data may be unknown.
type PartialEntities struct {
	entities map[types.EntityUID]PartialEntity
}

// NewPartialEntities creates a new empty PartialEntities collection.
func NewPartialEntities() *PartialEntities {
	return &PartialEntities{
		entities: make(map[types.EntityUID]PartialEntity),
	}
}

// PartialEntitiesFromSlice creates a PartialEntities collection from a slice.
func PartialEntitiesFromSlice(entities []PartialEntity) *PartialEntities {
	pe := NewPartialEntities()
	for _, e := range entities {
		pe.Add(e)
	}
	return pe
}

// PartialEntitiesFromEntityMap creates a PartialEntities collection from a concrete EntityMap.
// All entities will be fully known.
func PartialEntitiesFromEntityMap(entities types.EntityMap) *PartialEntities {
	pe := NewPartialEntities()
	for _, e := range entities {
		pe.Add(PartialEntityFromConcrete(e))
	}
	return pe
}

// Add adds or replaces a PartialEntity in the collection.
func (pe *PartialEntities) Add(e PartialEntity) {
	pe.entities[e.UID] = e
}

// Get retrieves a PartialEntity by its UID.
// Returns the entity and true if found, or a zero value and false if not found.
func (pe *PartialEntities) Get(uid types.EntityUID) (PartialEntity, bool) {
	e, ok := pe.entities[uid]
	return e, ok
}

// Contains returns true if the collection contains an entity with the given UID.
func (pe *PartialEntities) Contains(uid types.EntityUID) bool {
	_, ok := pe.entities[uid]
	return ok
}

// Len returns the number of entities in the collection.
func (pe *PartialEntities) Len() int {
	return len(pe.entities)
}

// All returns an iterator over all entities in the collection.
func (pe *PartialEntities) All() map[types.EntityUID]PartialEntity {
	return pe.entities
}

// ToEntityMap converts the collection to a concrete EntityMap.
// Unknown fields in partial entities are replaced with empty values.
func (pe *PartialEntities) ToEntityMap() types.EntityMap {
	result := make(types.EntityMap, len(pe.entities))
	for uid, e := range pe.entities {
		result[uid] = e.ToEntity()
	}
	return result
}

// FullyKnownEntities returns only the entities that are fully known.
func (pe *PartialEntities) FullyKnownEntities() types.EntityMap {
	result := make(types.EntityMap)
	for uid, e := range pe.entities {
		if e.IsFullyKnown() {
			result[uid] = e.ToEntity()
		}
	}
	return result
}

// PartialEntityUIDs returns the UIDs of entities that have unknown fields.
func (pe *PartialEntities) PartialEntityUIDs() []types.EntityUID {
	var result []types.EntityUID
	for uid, e := range pe.entities {
		if !e.IsFullyKnown() {
			result = append(result, uid)
		}
	}
	return result
}
