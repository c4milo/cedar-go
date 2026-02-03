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
	"testing"

	"github.com/cedar-policy/cedar-go/internal/testutil"
	"github.com/cedar-policy/cedar-go/types"
)

func TestPartialEntityUID(t *testing.T) {
	t.Parallel()

	t.Run("with known ID", func(t *testing.T) {
		id := types.String("alice")
		p := NewPartialEntityUID("User", &id)

		testutil.Equals(t, p.Type, types.EntityType("User"))
		testutil.Equals(t, p.IsKnown(), true)
		testutil.Equals(t, *p.ID, types.String("alice"))

		uid := p.ToEntityUID()
		testutil.Equals(t, uid.Type, types.EntityType("User"))
		testutil.Equals(t, uid.ID, types.String("alice"))
	})

	t.Run("with unknown ID", func(t *testing.T) {
		p := NewPartialEntityUID("User", nil)

		testutil.Equals(t, p.Type, types.EntityType("User"))
		testutil.Equals(t, p.IsKnown(), false)
		testutil.Equals(t, p.ID == nil, true)
	})

	t.Run("from concrete", func(t *testing.T) {
		uid := types.NewEntityUID("User", "alice")
		p := PartialEntityUIDFromConcrete(uid)

		testutil.Equals(t, p.IsKnown(), true)
		testutil.Equals(t, p.Type, types.EntityType("User"))
		testutil.Equals(t, *p.ID, types.String("alice"))
	})

	t.Run("ToEntityUID panics with unknown ID", func(t *testing.T) {
		p := NewPartialEntityUID("User", nil)

		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when converting partial UID with unknown ID")
			}
		}()

		p.ToEntityUID()
	})
}

func TestPartialEntity(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	attrs := types.NewRecord(types.RecordMap{
		"name": types.String("Alice"),
		"age":  types.Long(30),
	})
	ancestors := types.NewEntityUIDSet(types.NewEntityUID("Group", "admins"))
	tags := types.NewRecord(types.RecordMap{
		"role": types.String("admin"),
	})

	t.Run("fully known", func(t *testing.T) {
		p := NewPartialEntity(alice, &attrs, &ancestors, &tags)

		testutil.Equals(t, p.UID, alice)
		testutil.Equals(t, p.IsFullyKnown(), true)
		testutil.Equals(t, p.HasKnownAttributes(), true)
		testutil.Equals(t, p.HasKnownAncestors(), true)
		testutil.Equals(t, p.HasKnownTags(), true)
	})

	t.Run("unknown attributes", func(t *testing.T) {
		p := NewPartialEntity(alice, nil, &ancestors, &tags)

		testutil.Equals(t, p.IsFullyKnown(), false)
		testutil.Equals(t, p.HasKnownAttributes(), false)
		testutil.Equals(t, p.HasKnownAncestors(), true)
		testutil.Equals(t, p.HasKnownTags(), true)
	})

	t.Run("unknown ancestors", func(t *testing.T) {
		p := NewPartialEntity(alice, &attrs, nil, &tags)

		testutil.Equals(t, p.IsFullyKnown(), false)
		testutil.Equals(t, p.HasKnownAttributes(), true)
		testutil.Equals(t, p.HasKnownAncestors(), false)
		testutil.Equals(t, p.HasKnownTags(), true)
	})

	t.Run("unknown tags", func(t *testing.T) {
		p := NewPartialEntity(alice, &attrs, &ancestors, nil)

		testutil.Equals(t, p.IsFullyKnown(), false)
		testutil.Equals(t, p.HasKnownAttributes(), true)
		testutil.Equals(t, p.HasKnownAncestors(), true)
		testutil.Equals(t, p.HasKnownTags(), false)
	})

	t.Run("all unknown", func(t *testing.T) {
		p := NewPartialEntity(alice, nil, nil, nil)

		testutil.Equals(t, p.IsFullyKnown(), false)
		testutil.Equals(t, p.HasKnownAttributes(), false)
		testutil.Equals(t, p.HasKnownAncestors(), false)
		testutil.Equals(t, p.HasKnownTags(), false)
	})

	t.Run("from concrete", func(t *testing.T) {
		e := types.Entity{
			UID:        alice,
			Attributes: attrs,
			Parents:    ancestors,
			Tags:       tags,
		}
		p := PartialEntityFromConcrete(e)

		testutil.Equals(t, p.IsFullyKnown(), true)
		testutil.Equals(t, p.UID, alice)
	})

	t.Run("ToEntity with all known", func(t *testing.T) {
		p := NewPartialEntity(alice, &attrs, &ancestors, &tags)
		e := p.ToEntity()

		testutil.Equals(t, e.UID, alice)
		testutil.Equals(t, e.Attributes, attrs)
		testutil.Equals(t, e.Parents, ancestors)
		testutil.Equals(t, e.Tags, tags)
	})

	t.Run("ToEntity with unknown fields", func(t *testing.T) {
		p := NewPartialEntity(alice, nil, nil, nil)
		e := p.ToEntity()

		testutil.Equals(t, e.UID, alice)
		// Unknown fields should be empty/zero values
	})
}

func TestPartialEntities(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	bob := types.NewEntityUID("User", "bob")
	attrs := types.NewRecord(types.RecordMap{"name": types.String("Test")})
	ancestors := types.NewEntityUIDSet()

	t.Run("new empty", func(t *testing.T) {
		pe := NewPartialEntities()
		testutil.Equals(t, pe.Len(), 0)
	})

	t.Run("add and get", func(t *testing.T) {
		pe := NewPartialEntities()

		p := NewPartialEntity(alice, &attrs, &ancestors, nil)
		pe.Add(p)

		testutil.Equals(t, pe.Len(), 1)
		testutil.Equals(t, pe.Contains(alice), true)
		testutil.Equals(t, pe.Contains(bob), false)

		got, ok := pe.Get(alice)
		testutil.Equals(t, ok, true)
		testutil.Equals(t, got.UID, alice)
	})

	t.Run("from slice", func(t *testing.T) {
		entities := []PartialEntity{
			NewPartialEntity(alice, &attrs, &ancestors, nil),
			NewPartialEntity(bob, nil, nil, nil),
		}
		pe := PartialEntitiesFromSlice(entities)

		testutil.Equals(t, pe.Len(), 2)
		testutil.Equals(t, pe.Contains(alice), true)
		testutil.Equals(t, pe.Contains(bob), true)
	})

	t.Run("from entity map", func(t *testing.T) {
		em := types.EntityMap{
			alice: {UID: alice, Attributes: attrs, Parents: ancestors},
		}
		pe := PartialEntitiesFromEntityMap(em)

		testutil.Equals(t, pe.Len(), 1)

		got, ok := pe.Get(alice)
		testutil.Equals(t, ok, true)
		testutil.Equals(t, got.IsFullyKnown(), true)
	})

	t.Run("to entity map", func(t *testing.T) {
		pe := NewPartialEntities()
		pe.Add(NewPartialEntity(alice, &attrs, &ancestors, nil))
		pe.Add(NewPartialEntity(bob, nil, nil, nil))

		em := pe.ToEntityMap()
		testutil.Equals(t, len(em), 2)
	})

	t.Run("fully known entities", func(t *testing.T) {
		pe := NewPartialEntities()
		tags := types.NewRecord(types.RecordMap{})
		pe.Add(NewPartialEntity(alice, &attrs, &ancestors, &tags)) // fully known
		pe.Add(NewPartialEntity(bob, nil, nil, nil))               // partial

		known := pe.FullyKnownEntities()
		testutil.Equals(t, len(known), 1)
		_, ok := known[alice]
		testutil.Equals(t, ok, true)
	})

	t.Run("partial entity UIDs", func(t *testing.T) {
		pe := NewPartialEntities()
		tags := types.NewRecord(types.RecordMap{})
		pe.Add(NewPartialEntity(alice, &attrs, &ancestors, &tags)) // fully known
		pe.Add(NewPartialEntity(bob, nil, nil, nil))               // partial

		partial := pe.PartialEntityUIDs()
		testutil.Equals(t, len(partial), 1)
		testutil.Equals(t, partial[0], bob)
	})

	t.Run("all", func(t *testing.T) {
		pe := NewPartialEntities()
		pe.Add(NewPartialEntity(alice, &attrs, &ancestors, nil))
		pe.Add(NewPartialEntity(bob, nil, nil, nil))

		all := pe.All()
		testutil.Equals(t, len(all), 2)
	})

	t.Run("get not found", func(t *testing.T) {
		pe := NewPartialEntities()
		_, ok := pe.Get(alice)
		testutil.Equals(t, ok, false)
	})
}
