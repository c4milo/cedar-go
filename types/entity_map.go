package types

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
)

// An EntityGetter is an interface for retrieving an Entity by EntityUID.
type EntityGetter interface {
	Get(uid EntityUID) (Entity, bool)
}

var _ EntityGetter = EntityMap{}

// An EntityMap is a collection of all the entities that are needed to evaluate
// authorization requests.  The key is an EntityUID which uniquely identifies
// the Entity (it must be the same as the UID within the Entity itself.)
type EntityMap map[EntityUID]Entity

func (e EntityMap) MarshalJSON() ([]byte, error) {
	s := slices.Collect(maps.Values(e))
	slices.SortFunc(s, func(a, b Entity) int {
		return strings.Compare(a.UID.String(), b.UID.String())
	})
	return json.Marshal(s)
}

func (e *EntityMap) UnmarshalJSON(b []byte) error {
	var s []Entity
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	var res = EntityMap{}
	for _, e := range s {
		res[e.UID] = e
	}
	*e = res
	return nil
}

func (e EntityMap) Clone() EntityMap {
	return maps.Clone(e)
}

func (e EntityMap) Get(uid EntityUID) (Entity, bool) {
	ent, ok := e[uid]
	return ent, ok
}

// Upsert adds or updates an entity in the map and returns a new EntityMap.
// The original map is not modified. If the entity already exists, it is replaced.
// The entity's UID field is used as the key.
func (e EntityMap) Upsert(entity Entity) EntityMap {
	result := e.Clone()
	result[entity.UID] = entity
	return result
}

// UpsertAll adds or updates multiple entities in the map and returns a new EntityMap.
// The original map is not modified.
func (e EntityMap) UpsertAll(entities ...Entity) EntityMap {
	result := e.Clone()
	for _, entity := range entities {
		result[entity.UID] = entity
	}
	return result
}

// Remove removes an entity from the map by its UID and returns a new EntityMap.
// The original map is not modified. If the entity does not exist, the returned
// map is equivalent to Clone().
func (e EntityMap) Remove(uid EntityUID) EntityMap {
	result := e.Clone()
	delete(result, uid)
	return result
}

// RemoveAll removes multiple entities from the map by their UIDs and returns a new EntityMap.
// The original map is not modified.
func (e EntityMap) RemoveAll(uids ...EntityUID) EntityMap {
	result := e.Clone()
	for _, uid := range uids {
		delete(result, uid)
	}
	return result
}

// Contains returns true if the entity with the given UID exists in the map.
func (e EntityMap) Contains(uid EntityUID) bool {
	_, ok := e[uid]
	return ok
}

// Len returns the number of entities in the map.
func (e EntityMap) Len() int {
	return len(e)
}

// All returns an iterator over all entities in the map.
// The iteration order is not guaranteed.
func (e EntityMap) All() func(yield func(EntityUID, Entity) bool) {
	return func(yield func(EntityUID, Entity) bool) {
		for uid, entity := range e {
			if !yield(uid, entity) {
				return
			}
		}
	}
}

// UIDs returns an iterator over all entity UIDs in the map.
// The iteration order is not guaranteed.
func (e EntityMap) UIDs() func(yield func(EntityUID) bool) {
	return func(yield func(EntityUID) bool) {
		for uid := range e {
			if !yield(uid) {
				return
			}
		}
	}
}
