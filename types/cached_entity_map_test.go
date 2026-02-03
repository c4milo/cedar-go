package types

import (
	"fmt"
	"testing"

	"github.com/cedar-policy/cedar-go/internal/testutil"
)

func TestAncestryCache(t *testing.T) {
	t.Parallel()

	t.Run("empty entities", func(t *testing.T) {
		t.Parallel()
		entities := EntityMap{}
		cache := NewAncestryCache(entities, entities.UIDs())

		ancestors := cache.GetAncestors(NewEntityUID("User", "alice"))
		testutil.Equals(t, ancestors.Len(), 0)
	})

	t.Run("single entity no parents", func(t *testing.T) {
		t.Parallel()
		alice := NewEntityUID("User", "alice")
		entities := EntityMap{
			alice: Entity{UID: alice},
		}
		cache := NewAncestryCache(entities, entities.UIDs())

		ancestors := cache.GetAncestors(alice)
		testutil.Equals(t, ancestors.Len(), 0)
	})

	t.Run("direct parent", func(t *testing.T) {
		t.Parallel()
		alice := NewEntityUID("User", "alice")
		admins := NewEntityUID("Group", "admins")
		entities := EntityMap{
			alice: Entity{
				UID:     alice,
				Parents: NewEntityUIDSet(admins),
			},
			admins: Entity{UID: admins},
		}
		cache := NewAncestryCache(entities, entities.UIDs())

		ancestors := cache.GetAncestors(alice)
		testutil.Equals(t, ancestors.Len(), 1)
		testutil.Equals(t, ancestors.Contains(admins), true)
	})

	t.Run("transitive ancestors", func(t *testing.T) {
		t.Parallel()
		// alice -> admins -> root
		alice := NewEntityUID("User", "alice")
		admins := NewEntityUID("Group", "admins")
		root := NewEntityUID("Group", "root")

		entities := EntityMap{
			alice: Entity{
				UID:     alice,
				Parents: NewEntityUIDSet(admins),
			},
			admins: Entity{
				UID:     admins,
				Parents: NewEntityUIDSet(root),
			},
			root: Entity{UID: root},
		}
		cache := NewAncestryCache(entities, entities.UIDs())

		ancestors := cache.GetAncestors(alice)
		testutil.Equals(t, ancestors.Len(), 2)
		testutil.Equals(t, ancestors.Contains(admins), true)
		testutil.Equals(t, ancestors.Contains(root), true)
	})

	t.Run("diamond inheritance", func(t *testing.T) {
		t.Parallel()
		// alice -> admins -> root
		// alice -> devs -> root
		alice := NewEntityUID("User", "alice")
		admins := NewEntityUID("Group", "admins")
		devs := NewEntityUID("Group", "devs")
		root := NewEntityUID("Group", "root")

		entities := EntityMap{
			alice: Entity{
				UID:     alice,
				Parents: NewEntityUIDSet(admins, devs),
			},
			admins: Entity{
				UID:     admins,
				Parents: NewEntityUIDSet(root),
			},
			devs: Entity{
				UID:     devs,
				Parents: NewEntityUIDSet(root),
			},
			root: Entity{UID: root},
		}
		cache := NewAncestryCache(entities, entities.UIDs())

		ancestors := cache.GetAncestors(alice)
		testutil.Equals(t, ancestors.Len(), 3)
		testutil.Equals(t, ancestors.Contains(admins), true)
		testutil.Equals(t, ancestors.Contains(devs), true)
		testutil.Equals(t, ancestors.Contains(root), true)
	})

	t.Run("cyclic graph", func(t *testing.T) {
		t.Parallel()
		// a -> b -> c -> a (cycle)
		a := NewEntityUID("Node", "a")
		b := NewEntityUID("Node", "b")
		c := NewEntityUID("Node", "c")

		entities := EntityMap{
			a: Entity{UID: a, Parents: NewEntityUIDSet(b)},
			b: Entity{UID: b, Parents: NewEntityUIDSet(c)},
			c: Entity{UID: c, Parents: NewEntityUIDSet(a)},
		}
		cache := NewAncestryCache(entities, entities.UIDs())

		// Should not infinite loop - ancestors should contain all nodes
		ancestors := cache.GetAncestors(a)
		testutil.Equals(t, ancestors.Contains(b), true)
		testutil.Equals(t, ancestors.Contains(c), true)
	})
}

func TestAncestryCache_IsAncestor(t *testing.T) {
	t.Parallel()

	alice := NewEntityUID("User", "alice")
	admins := NewEntityUID("Group", "admins")
	root := NewEntityUID("Group", "root")
	unrelated := NewEntityUID("Group", "unrelated")

	entities := EntityMap{
		alice: Entity{
			UID:     alice,
			Parents: NewEntityUIDSet(admins),
		},
		admins: Entity{
			UID:     admins,
			Parents: NewEntityUIDSet(root),
		},
		root:      Entity{UID: root},
		unrelated: Entity{UID: unrelated},
	}
	cache := NewAncestryCache(entities, entities.UIDs())

	t.Run("self is ancestor", func(t *testing.T) {
		t.Parallel()
		testutil.Equals(t, cache.IsAncestor(alice, alice), true)
	})

	t.Run("direct parent is ancestor", func(t *testing.T) {
		t.Parallel()
		testutil.Equals(t, cache.IsAncestor(alice, admins), true)
	})

	t.Run("transitive ancestor", func(t *testing.T) {
		t.Parallel()
		testutil.Equals(t, cache.IsAncestor(alice, root), true)
	})

	t.Run("not ancestor", func(t *testing.T) {
		t.Parallel()
		testutil.Equals(t, cache.IsAncestor(alice, unrelated), false)
	})

	t.Run("child is not ancestor of parent", func(t *testing.T) {
		t.Parallel()
		testutil.Equals(t, cache.IsAncestor(admins, alice), false)
	})
}

func TestAncestryCache_IsAncestorOfAny(t *testing.T) {
	t.Parallel()

	alice := NewEntityUID("User", "alice")
	admins := NewEntityUID("Group", "admins")
	root := NewEntityUID("Group", "root")
	unrelated := NewEntityUID("Group", "unrelated")

	entities := EntityMap{
		alice:     Entity{UID: alice, Parents: NewEntityUIDSet(admins)},
		admins:    Entity{UID: admins, Parents: NewEntityUIDSet(root)},
		root:      Entity{UID: root},
		unrelated: Entity{UID: unrelated},
	}
	cache := NewAncestryCache(entities, entities.UIDs())

	t.Run("self in candidates", func(t *testing.T) {
		t.Parallel()
		testutil.Equals(t, cache.IsAncestorOfAny(alice, NewEntityUIDSet(alice)), true)
	})

	t.Run("ancestor in candidates", func(t *testing.T) {
		t.Parallel()
		testutil.Equals(t, cache.IsAncestorOfAny(alice, NewEntityUIDSet(root, unrelated)), true)
	})

	t.Run("no ancestor in candidates", func(t *testing.T) {
		t.Parallel()
		testutil.Equals(t, cache.IsAncestorOfAny(alice, NewEntityUIDSet(unrelated)), false)
	})
}

func TestCachedEntityGetter(t *testing.T) {
	t.Parallel()

	alice := NewEntityUID("User", "alice")
	admins := NewEntityUID("Group", "admins")
	entities := EntityMap{
		alice:  Entity{UID: alice, Parents: NewEntityUIDSet(admins)},
		admins: Entity{UID: admins},
	}

	t.Run("implements EntityGetter", func(t *testing.T) {
		t.Parallel()
		cached := NewCachedEntityGetter(entities)

		entity, ok := cached.Get(alice)
		testutil.Equals(t, ok, true)
		testutil.Equals(t, entity.UID, alice)

		_, ok = cached.Get(NewEntityUID("User", "nonexistent"))
		testutil.Equals(t, ok, false)
	})

	t.Run("implements AncestryCacheGetter", func(t *testing.T) {
		t.Parallel()
		cached := NewCachedEntityGetter(entities)
		var _ AncestryCacheGetter = cached

		cache := cached.GetAncestryCache()
		testutil.Equals(t, cache != nil, true)
		testutil.Equals(t, cache.IsAncestor(alice, admins), true)
	})
}

// Benchmark to measure cache performance improvement
func BenchmarkEntityHierarchyTraversal(b *testing.B) {
	depths := []int{5, 10, 20, 50}

	for _, depth := range depths {
		// Build a deep hierarchy: user -> g0 -> g1 -> ... -> root
		entities := EntityMap{}
		prevUID := NewEntityUID("Group", "root")
		entities[prevUID] = Entity{UID: prevUID}

		for i := depth - 1; i >= 0; i-- {
			uid := NewEntityUID("Group", String(fmt.Sprintf("g%d", i)))
			entities[uid] = Entity{UID: uid, Parents: NewEntityUIDSet(prevUID)}
			prevUID = uid
		}

		userUID := NewEntityUID("User", "alice")
		entities[userUID] = Entity{UID: userUID, Parents: NewEntityUIDSet(prevUID)}
		root := NewEntityUID("Group", "root")

		b.Run(fmt.Sprintf("uncached/depth=%d", depth), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Simulate the "in" check without cache
				found := false
				current := userUID
				for !found {
					entity, ok := entities.Get(current)
					if !ok {
						break
					}
					if entity.Parents.Contains(root) {
						found = true
						break
					}
					// Move to first parent
					for p := range entity.Parents.All() {
						current = p
						break
					}
					if current == userUID {
						break // No more parents
					}
				}
			}
		})

		b.Run(fmt.Sprintf("cached/depth=%d", depth), func(b *testing.B) {
			cached := NewCachedEntityGetter(entities)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cached.GetAncestryCache().IsAncestor(userUID, root)
			}
		})
	}
}
