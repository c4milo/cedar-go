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
	"context"
	"maps"

	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
)

// EntityLoader provides on-demand entity loading for partial evaluation.
// This is useful when you have a large entity store or when entities
// are fetched from an external service (database, API, etc.).
//
// Unlike [types.EntityGetter], EntityLoader supports:
//   - Batch loading of multiple entities at once
//   - Context-aware loading with cancellation support
//   - Error handling for load failures
//
// EntityLoader is particularly useful for TPE (Template Policy Engine)
// scenarios where you want to partially evaluate policies and only load
// the entities that are actually needed.
type EntityLoader interface {
	// Load retrieves entities for the given UIDs.
	// It returns a map of the loaded entities (only those that exist)
	// and any error that occurred during loading.
	//
	// The returned map may contain fewer entries than requested UIDs
	// if some entities don't exist. Missing entities are not an error.
	//
	// Implementations should be efficient for batch loading.
	Load(ctx context.Context, uids []types.EntityUID) (types.EntityMap, error)
}

// EntityLoaderFunc is an adapter to allow using ordinary functions
// as EntityLoaders.
type EntityLoaderFunc func(ctx context.Context, uids []types.EntityUID) (types.EntityMap, error)

// Load implements EntityLoader.
func (f EntityLoaderFunc) Load(ctx context.Context, uids []types.EntityUID) (types.EntityMap, error) {
	return f(ctx, uids)
}

// MapEntityLoader wraps an EntityMap to implement EntityLoader.
// This is useful when you already have all entities in memory.
type MapEntityLoader struct {
	entities types.EntityMap
}

// NewMapEntityLoader creates an EntityLoader backed by an EntityMap.
func NewMapEntityLoader(entities types.EntityMap) *MapEntityLoader {
	return &MapEntityLoader{entities: entities}
}

// Load implements EntityLoader by looking up entities in the underlying map.
func (m *MapEntityLoader) Load(_ context.Context, uids []types.EntityUID) (types.EntityMap, error) {
	result := make(types.EntityMap, len(uids))
	for _, uid := range uids {
		if entity, ok := m.entities[uid]; ok {
			result[uid] = entity
		}
	}
	return result, nil
}

// TrackingEntityLoader wraps an EntityLoader to track which entities are accessed.
// This is useful for:
//   - Understanding which entities a policy actually needs
//   - Building entity slices for caching
//   - Debugging evaluation behavior
type TrackingEntityLoader struct {
	loader   EntityLoader
	accessed types.EntityMap
}

// NewTrackingEntityLoader creates an EntityLoader that tracks accessed entities.
func NewTrackingEntityLoader(loader EntityLoader) *TrackingEntityLoader {
	return &TrackingEntityLoader{
		loader:   loader,
		accessed: make(types.EntityMap),
	}
}

// Load implements EntityLoader and tracks accessed entities.
func (t *TrackingEntityLoader) Load(ctx context.Context, uids []types.EntityUID) (types.EntityMap, error) {
	result, err := t.loader.Load(ctx, uids)
	if err != nil {
		return nil, err
	}
	// Track all loaded entities
	maps.Copy(t.accessed, result)
	return result, nil
}

// Accessed returns all entities that have been loaded through this loader.
func (t *TrackingEntityLoader) Accessed() types.EntityMap {
	return t.accessed.Clone()
}

// Reset clears the tracking state.
func (t *TrackingEntityLoader) Reset() {
	t.accessed = make(types.EntityMap)
}

// CachingEntityLoader wraps an EntityLoader to cache loaded entities.
// Once an entity is loaded, subsequent requests return the cached value
// without calling the underlying loader.
type CachingEntityLoader struct {
	loader EntityLoader
	cache  types.EntityMap
	// Track UIDs that were requested but not found, to avoid repeated lookups
	notFound map[types.EntityUID]struct{}
}

// NewCachingEntityLoader creates an EntityLoader with caching.
func NewCachingEntityLoader(loader EntityLoader) *CachingEntityLoader {
	return &CachingEntityLoader{
		loader:   loader,
		cache:    make(types.EntityMap),
		notFound: make(map[types.EntityUID]struct{}),
	}
}

// Load implements EntityLoader with caching.
func (c *CachingEntityLoader) Load(ctx context.Context, uids []types.EntityUID) (types.EntityMap, error) {
	result := make(types.EntityMap, len(uids))
	var toLoad []types.EntityUID

	// Check cache first
	for _, uid := range uids {
		if entity, ok := c.cache[uid]; ok {
			result[uid] = entity
		} else if _, notFound := c.notFound[uid]; !notFound {
			toLoad = append(toLoad, uid)
		}
	}

	// Load missing entities
	if len(toLoad) > 0 {
		loaded, err := c.loader.Load(ctx, toLoad)
		if err != nil {
			return nil, err
		}

		// Update cache and result
		for _, uid := range toLoad {
			if entity, ok := loaded[uid]; ok {
				c.cache[uid] = entity
				result[uid] = entity
			} else {
				c.notFound[uid] = struct{}{}
			}
		}
	}

	return result, nil
}

// Cache returns the current cache contents.
func (c *CachingEntityLoader) Cache() types.EntityMap {
	return c.cache.Clone()
}

// ClearCache clears the cache, allowing entities to be reloaded.
func (c *CachingEntityLoader) ClearCache() {
	c.cache = make(types.EntityMap)
	c.notFound = make(map[types.EntityUID]struct{})
}

// LoadingEntityGetter adapts an EntityLoader to implement types.EntityGetter.
// This allows using an EntityLoader where an EntityGetter is expected.
//
// Note: This adapter loads entities synchronously with a background context.
// For production use with external services, prefer using EntityLoader directly
// with proper context handling.
type LoadingEntityGetter struct {
	loader EntityLoader
	ctx    context.Context
}

// NewLoadingEntityGetter creates an EntityGetter backed by an EntityLoader.
// The provided context is used for all Load calls.
func NewLoadingEntityGetter(ctx context.Context, loader EntityLoader) *LoadingEntityGetter {
	return &LoadingEntityGetter{
		loader: loader,
		ctx:    ctx,
	}
}

// Get implements types.EntityGetter.
func (l *LoadingEntityGetter) Get(uid types.EntityUID) (types.Entity, bool) {
	result, err := l.loader.Load(l.ctx, []types.EntityUID{uid})
	if err != nil {
		return types.Entity{}, false
	}
	entity, ok := result[uid]
	return entity, ok
}

// CollectReferencedEntities finds all entity UIDs referenced in a residual policy.
// This is useful for determining which entities need to be loaded for
// further evaluation of a partially evaluated policy.
func CollectReferencedEntities(p *ast.Policy) []types.EntityUID {
	if p == nil {
		return nil
	}

	var uids []types.EntityUID
	seen := make(map[types.EntityUID]struct{})

	// Check scopes for entity references
	collectScopeEntities(&uids, &seen, p.Principal)
	collectScopeEntities(&uids, &seen, p.Action)
	collectScopeEntities(&uids, &seen, p.Resource)

	// Check conditions
	for _, cond := range p.Conditions {
		collectNodeEntities(&uids, &seen, cond.Body)
	}

	return uids
}

func collectScopeEntities(uids *[]types.EntityUID, seen *map[types.EntityUID]struct{}, scope ast.IsScopeNode) {
	switch s := scope.(type) {
	case ast.ScopeTypeEq:
		addUID(uids, seen, s.Entity)
	case ast.ScopeTypeIn:
		addUID(uids, seen, s.Entity)
	case ast.ScopeTypeInSet:
		for _, e := range s.Entities {
			addUID(uids, seen, e)
		}
	case ast.ScopeTypeIsIn:
		addUID(uids, seen, s.Entity)
	}
}

func collectNodeEntities(uids *[]types.EntityUID, seen *map[types.EntityUID]struct{}, n ast.IsNode) {
	if n == nil {
		return
	}

	if v, ok := n.(ast.NodeValue); ok {
		collectValueEntities(uids, seen, v.Value)
		return
	}

	for _, child := range getNodeChildren(n) {
		collectNodeEntities(uids, seen, child)
	}
}

func collectValueEntities(uids *[]types.EntityUID, seen *map[types.EntityUID]struct{}, v types.Value) {
	switch t := v.(type) {
	case types.EntityUID:
		// Don't add variable markers
		if _, isVar := ToVariable(t); !isVar {
			addUID(uids, seen, t)
		}
	case types.Record:
		for val := range t.Values() {
			collectValueEntities(uids, seen, val)
		}
	case types.Set:
		for val := range t.All() {
			collectValueEntities(uids, seen, val)
		}
	}
}

func addUID(uids *[]types.EntityUID, seen *map[types.EntityUID]struct{}, uid types.EntityUID) {
	if _, ok := (*seen)[uid]; !ok {
		(*seen)[uid] = struct{}{}
		*uids = append(*uids, uid)
	}
}
