package types_test

import (
	"encoding/json"
	"testing"

	"github.com/cedar-policy/cedar-go/internal/testutil"
	"github.com/cedar-policy/cedar-go/types"
)

func TestEntities(t *testing.T) {
	t.Parallel()
	t.Run("Clone", func(t *testing.T) {
		t.Parallel()
		e := types.EntityMap{
			types.EntityUID{Type: "A", ID: "A"}: {},
			types.EntityUID{Type: "A", ID: "B"}: {},
			types.EntityUID{Type: "B", ID: "A"}: {},
			types.EntityUID{Type: "B", ID: "B"}: {},
		}
		clone := e.Clone()
		testutil.Equals(t, clone, e)
	})

	t.Run("Get", func(t *testing.T) {
		t.Parallel()
		ent := types.Entity{
			UID:        types.NewEntityUID("Type", "id"),
			Attributes: types.NewRecord(types.RecordMap{"key": types.Long(42)}),
		}
		e := types.EntityMap{
			ent.UID: ent,
		}
		got, ok := e.Get(ent.UID)
		testutil.Equals(t, ok, true)
		testutil.Equals(t, got, ent)
		_, ok = e.Get(types.NewEntityUID("Type", "id2"))
		testutil.Equals(t, ok, false)
	})
}

func TestEntitiesJSON(t *testing.T) {
	t.Parallel()
	t.Run("Marshal", func(t *testing.T) {
		t.Parallel()
		e := types.EntityMap{}
		ent := types.Entity{
			UID:        types.NewEntityUID("Type", "id"),
			Parents:    types.EntityUIDSet{},
			Attributes: types.NewRecord(types.RecordMap{"key": types.Long(42)}),
		}
		ent2 := types.Entity{
			UID:        types.NewEntityUID("Type", "id2"),
			Parents:    types.NewEntityUIDSet(ent.UID),
			Attributes: types.NewRecord(types.RecordMap{"key": types.Long(42)}),
		}
		e[ent.UID] = ent
		e[ent2.UID] = ent2
		testutil.JSONMarshalsTo(
			t,
			e,
			`[
				{"uid": {"type": "Type", "id": "id"}, "parents": [], "attrs": {"key": 42}, "tags": {}},
				{"uid": {"type": "Type" ,"id" :"id2"}, "parents": [{"type":"Type","id":"id"}], "attrs": {"key": 42}, "tags":{}}
			]`)
	})

	t.Run("Unmarshal", func(t *testing.T) {
		t.Parallel()
		b := []byte(`[{"uid":{"type":"Type","id":"id"},"parents":[],"attrs":{"key":42}}]`)
		var e types.EntityMap
		err := json.Unmarshal(b, &e)
		testutil.OK(t, err)
		want := types.EntityMap{}
		ent := types.Entity{
			UID:        types.NewEntityUID("Type", "id"),
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.NewRecord(types.RecordMap{"key": types.Long(42)}),
		}
		want[ent.UID] = ent
		testutil.Equals(t, e, want)
	})

	t.Run("UnmarshalErr", func(t *testing.T) {
		t.Parallel()
		var e types.EntityMap
		err := e.UnmarshalJSON([]byte(`!@#$`))
		testutil.Error(t, err)
	})
}

func TestEntitiesMutation(t *testing.T) {
	t.Parallel()

	t.Run("Upsert_New", func(t *testing.T) {
		t.Parallel()
		e := types.EntityMap{}
		ent := types.Entity{
			UID:        types.NewEntityUID("User", "alice"),
			Attributes: types.NewRecord(types.RecordMap{"name": types.String("Alice")}),
		}

		result := e.Upsert(ent)

		// Original should be unchanged
		testutil.Equals(t, len(e), 0)

		// Result should contain the new entity
		testutil.Equals(t, len(result), 1)
		got, ok := result.Get(ent.UID)
		testutil.Equals(t, ok, true)
		testutil.Equals(t, got, ent)
	})

	t.Run("Upsert_Update", func(t *testing.T) {
		t.Parallel()
		ent1 := types.Entity{
			UID:        types.NewEntityUID("User", "alice"),
			Attributes: types.NewRecord(types.RecordMap{"name": types.String("Alice")}),
		}
		e := types.EntityMap{ent1.UID: ent1}

		// Update with new attributes
		ent2 := types.Entity{
			UID:        types.NewEntityUID("User", "alice"),
			Attributes: types.NewRecord(types.RecordMap{"name": types.String("Alice Updated")}),
		}
		result := e.Upsert(ent2)

		// Original should be unchanged
		got, _ := e.Get(ent1.UID)
		name, _ := got.Attributes.Get("name")
		testutil.Equals(t, name, types.Value(types.String("Alice")))

		// Result should have updated entity
		got, _ = result.Get(ent2.UID)
		name, _ = got.Attributes.Get("name")
		testutil.Equals(t, name, types.Value(types.String("Alice Updated")))
	})

	t.Run("UpsertAll", func(t *testing.T) {
		t.Parallel()
		e := types.EntityMap{}
		ent1 := types.Entity{UID: types.NewEntityUID("User", "alice")}
		ent2 := types.Entity{UID: types.NewEntityUID("User", "bob")}
		ent3 := types.Entity{UID: types.NewEntityUID("User", "charlie")}

		result := e.UpsertAll(ent1, ent2, ent3)

		testutil.Equals(t, len(e), 0)
		testutil.Equals(t, len(result), 3)
		testutil.Equals(t, result.Contains(ent1.UID), true)
		testutil.Equals(t, result.Contains(ent2.UID), true)
		testutil.Equals(t, result.Contains(ent3.UID), true)
	})

	t.Run("Remove", func(t *testing.T) {
		t.Parallel()
		ent1 := types.Entity{UID: types.NewEntityUID("User", "alice")}
		ent2 := types.Entity{UID: types.NewEntityUID("User", "bob")}
		e := types.EntityMap{
			ent1.UID: ent1,
			ent2.UID: ent2,
		}

		result := e.Remove(ent1.UID)

		// Original unchanged
		testutil.Equals(t, len(e), 2)

		// Result has entity removed
		testutil.Equals(t, len(result), 1)
		testutil.Equals(t, result.Contains(ent1.UID), false)
		testutil.Equals(t, result.Contains(ent2.UID), true)
	})

	t.Run("Remove_NonExistent", func(t *testing.T) {
		t.Parallel()
		ent := types.Entity{UID: types.NewEntityUID("User", "alice")}
		e := types.EntityMap{ent.UID: ent}

		result := e.Remove(types.NewEntityUID("User", "nonexistent"))

		testutil.Equals(t, len(result), 1)
		testutil.Equals(t, result.Contains(ent.UID), true)
	})

	t.Run("RemoveAll", func(t *testing.T) {
		t.Parallel()
		ent1 := types.Entity{UID: types.NewEntityUID("User", "alice")}
		ent2 := types.Entity{UID: types.NewEntityUID("User", "bob")}
		ent3 := types.Entity{UID: types.NewEntityUID("User", "charlie")}
		e := types.EntityMap{
			ent1.UID: ent1,
			ent2.UID: ent2,
			ent3.UID: ent3,
		}

		result := e.RemoveAll(ent1.UID, ent2.UID)

		testutil.Equals(t, len(e), 3)
		testutil.Equals(t, len(result), 1)
		testutil.Equals(t, result.Contains(ent3.UID), true)
	})

	t.Run("Contains", func(t *testing.T) {
		t.Parallel()
		ent := types.Entity{UID: types.NewEntityUID("User", "alice")}
		e := types.EntityMap{ent.UID: ent}

		testutil.Equals(t, e.Contains(ent.UID), true)
		testutil.Equals(t, e.Contains(types.NewEntityUID("User", "bob")), false)
	})

	t.Run("Len", func(t *testing.T) {
		t.Parallel()
		e := types.EntityMap{}
		testutil.Equals(t, e.Len(), 0)

		e[types.NewEntityUID("User", "alice")] = types.Entity{}
		testutil.Equals(t, e.Len(), 1)

		e[types.NewEntityUID("User", "bob")] = types.Entity{}
		testutil.Equals(t, e.Len(), 2)
	})

	t.Run("All", func(t *testing.T) {
		t.Parallel()
		ent1 := types.Entity{UID: types.NewEntityUID("User", "alice")}
		ent2 := types.Entity{UID: types.NewEntityUID("User", "bob")}
		e := types.EntityMap{
			ent1.UID: ent1,
			ent2.UID: ent2,
		}

		count := 0
		seen := make(map[types.EntityUID]bool)
		for uid, entity := range e.All() {
			count++
			seen[uid] = true
			testutil.Equals(t, entity.UID, uid)
		}

		testutil.Equals(t, count, 2)
		testutil.Equals(t, seen[ent1.UID], true)
		testutil.Equals(t, seen[ent2.UID], true)
	})

	t.Run("All_EarlyBreak", func(t *testing.T) {
		t.Parallel()
		ent1 := types.Entity{UID: types.NewEntityUID("User", "alice")}
		ent2 := types.Entity{UID: types.NewEntityUID("User", "bob")}
		e := types.EntityMap{
			ent1.UID: ent1,
			ent2.UID: ent2,
		}

		count := 0
		for range e.All() {
			count++
			break
		}
		testutil.Equals(t, count, 1)
	})

	t.Run("UIDs", func(t *testing.T) {
		t.Parallel()
		ent1 := types.Entity{UID: types.NewEntityUID("User", "alice")}
		ent2 := types.Entity{UID: types.NewEntityUID("User", "bob")}
		e := types.EntityMap{
			ent1.UID: ent1,
			ent2.UID: ent2,
		}

		count := 0
		seen := make(map[types.EntityUID]bool)
		for uid := range e.UIDs() {
			count++
			seen[uid] = true
		}

		testutil.Equals(t, count, 2)
		testutil.Equals(t, seen[ent1.UID], true)
		testutil.Equals(t, seen[ent2.UID], true)
	})

	t.Run("UIDs_EarlyBreak", func(t *testing.T) {
		t.Parallel()
		ent1 := types.Entity{UID: types.NewEntityUID("User", "alice")}
		ent2 := types.Entity{UID: types.NewEntityUID("User", "bob")}
		e := types.EntityMap{
			ent1.UID: ent1,
			ent2.UID: ent2,
		}

		count := 0
		for range e.UIDs() {
			count++
			break
		}
		testutil.Equals(t, count, 1)
	})

	t.Run("Chained_Operations", func(t *testing.T) {
		t.Parallel()
		// Test that operations can be chained
		e := types.EntityMap{}
		ent1 := types.Entity{UID: types.NewEntityUID("User", "alice")}
		ent2 := types.Entity{UID: types.NewEntityUID("User", "bob")}
		ent3 := types.Entity{UID: types.NewEntityUID("User", "charlie")}

		result := e.Upsert(ent1).Upsert(ent2).Upsert(ent3).Remove(ent2.UID)

		testutil.Equals(t, len(result), 2)
		testutil.Equals(t, result.Contains(ent1.UID), true)
		testutil.Equals(t, result.Contains(ent2.UID), false)
		testutil.Equals(t, result.Contains(ent3.UID), true)
	})
}
