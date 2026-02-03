package types

import "github.com/cedar-policy/cedar-go/internal/mapset"

// AncestryCache stores precomputed transitive ancestors for each entity.
// Using this cache converts O(d) hierarchy traversals to O(1) set lookups,
// where d is the depth of the entity graph.
type AncestryCache struct {
	// ancestors maps each entity to all of its ancestors (transitive closure of parents)
	ancestors map[EntityUID]EntityUIDSet
}

// NewAncestryCache computes and returns an ancestry cache for the given entities.
// This performs a single traversal of the entity graph to compute the transitive
// closure of the parent relationship for all entities.
func NewAncestryCache(entities EntityGetter, allUIDs func(yield func(EntityUID) bool)) *AncestryCache {
	cache := &AncestryCache{
		ancestors: make(map[EntityUID]EntityUIDSet),
	}

	// For each entity, compute its complete set of ancestors
	for uid := range allUIDs {
		cache.computeAncestors(entities, uid)
	}

	return cache
}

// computeAncestors computes all ancestors for a single entity using memoization.
// Returns the set of all ancestors (transitive closure of parents).
func (c *AncestryCache) computeAncestors(entities EntityGetter, uid EntityUID) EntityUIDSet {
	// Check if already computed
	if ancestors, ok := c.ancestors[uid]; ok {
		return ancestors
	}

	// Mark as in-progress with empty set to handle cycles
	c.ancestors[uid] = EntityUIDSet{}

	entity, ok := entities.Get(uid)
	if !ok {
		// Entity doesn't exist, no ancestors
		return c.ancestors[uid]
	}

	// Build ancestors using mutable set, then convert to immutable
	ancestorSet := mapset.Make[EntityUID]()
	for parent := range entity.Parents.All() {
		// Add direct parent
		ancestorSet.Add(parent)
		// Add all ancestors of parent (recursive with memoization)
		parentAncestors := c.computeAncestors(entities, parent)
		for ancestor := range parentAncestors.All() {
			ancestorSet.Add(ancestor)
		}
	}

	// Convert to immutable set
	ancestors := NewEntityUIDSet(ancestorSet.Slice()...)
	c.ancestors[uid] = ancestors
	return ancestors
}

// GetAncestors returns the precomputed ancestors for the given entity.
// Returns an empty set if the entity is not in the cache.
func (c *AncestryCache) GetAncestors(uid EntityUID) EntityUIDSet {
	if ancestors, ok := c.ancestors[uid]; ok {
		return ancestors
	}
	return EntityUIDSet{}
}

// IsAncestor checks if 'ancestor' is an ancestor of 'entity'.
// This is an O(1) operation using the precomputed cache.
func (c *AncestryCache) IsAncestor(entity, ancestor EntityUID) bool {
	if entity == ancestor {
		return true
	}
	ancestors := c.GetAncestors(entity)
	return ancestors.Contains(ancestor)
}

// IsAncestorOfAny checks if any entity in 'candidates' is an ancestor of 'entity'.
// This is an O(|candidates|) operation using the precomputed cache.
func (c *AncestryCache) IsAncestorOfAny(entity EntityUID, candidates EntityUIDSet) bool {
	if candidates.Contains(entity) {
		return true
	}
	ancestors := c.GetAncestors(entity)
	return ancestors.Intersects(candidates)
}

// CachedEntityGetter wraps an EntityGetter with an ancestry cache for faster
// "in" operator evaluation.
type CachedEntityGetter struct {
	Entities EntityGetter
	Cache    *AncestryCache
}

// NewCachedEntityGetter creates a CachedEntityGetter from an EntityMap.
// The ancestry cache is computed during construction.
func NewCachedEntityGetter(entities EntityMap) *CachedEntityGetter {
	return &CachedEntityGetter{
		Entities: entities,
		Cache:    NewAncestryCache(entities, entities.UIDs()),
	}
}

// Get retrieves an entity by UID, implementing the EntityGetter interface.
func (c *CachedEntityGetter) Get(uid EntityUID) (Entity, bool) {
	return c.Entities.Get(uid)
}

// GetAncestryCache returns the precomputed ancestry cache.
func (c *CachedEntityGetter) GetAncestryCache() *AncestryCache {
	return c.Cache
}

// AncestryCacheGetter is an interface for EntityGetters that have an ancestry cache.
type AncestryCacheGetter interface {
	EntityGetter
	GetAncestryCache() *AncestryCache
}

// Ensure CachedEntityGetter implements the interface
var _ AncestryCacheGetter = (*CachedEntityGetter)(nil)
