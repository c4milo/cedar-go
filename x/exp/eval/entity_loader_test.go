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
	"errors"
	"slices"
	"testing"

	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
)

func TestMapEntityLoader(t *testing.T) {
	alice := types.NewEntityUID("User", "alice")
	bob := types.NewEntityUID("User", "bob")

	entities := types.EntityMap{
		alice: {UID: alice, Attributes: types.Record{}},
		bob:   {UID: bob, Attributes: types.Record{}},
	}

	loader := NewMapEntityLoader(entities)

	// Load existing entities
	result, err := loader.Load(context.Background(), []types.EntityUID{alice})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 entity, got %d", len(result))
	}
	if _, ok := result[alice]; !ok {
		t.Error("expected alice in result")
	}

	// Load non-existent entity
	charlie := types.NewEntityUID("User", "charlie")
	result, err = loader.Load(context.Background(), []types.EntityUID{charlie})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 entities, got %d", len(result))
	}

	// Load mixed
	result, err = loader.Load(context.Background(), []types.EntityUID{alice, charlie, bob})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 entities, got %d", len(result))
	}
}

func TestTrackingEntityLoader(t *testing.T) {
	alice := types.NewEntityUID("User", "alice")
	bob := types.NewEntityUID("User", "bob")

	entities := types.EntityMap{
		alice: {UID: alice, Attributes: types.Record{}},
		bob:   {UID: bob, Attributes: types.Record{}},
	}

	base := NewMapEntityLoader(entities)
	tracker := NewTrackingEntityLoader(base)

	// Initial state
	if len(tracker.Accessed()) != 0 {
		t.Error("expected no accessed entities initially")
	}

	// Load alice
	_, _ = tracker.Load(context.Background(), []types.EntityUID{alice})
	accessed := tracker.Accessed()
	if len(accessed) != 1 {
		t.Errorf("expected 1 accessed entity, got %d", len(accessed))
	}
	if _, ok := accessed[alice]; !ok {
		t.Error("expected alice in accessed")
	}

	// Load bob
	_, _ = tracker.Load(context.Background(), []types.EntityUID{bob})
	accessed = tracker.Accessed()
	if len(accessed) != 2 {
		t.Errorf("expected 2 accessed entities, got %d", len(accessed))
	}

	// Reset
	tracker.Reset()
	if len(tracker.Accessed()) != 0 {
		t.Error("expected no accessed entities after reset")
	}
}

func TestCachingEntityLoader(t *testing.T) {
	alice := types.NewEntityUID("User", "alice")
	loadCount := 0

	// Create a loader that counts calls
	countingLoader := EntityLoaderFunc(func(ctx context.Context, uids []types.EntityUID) (types.EntityMap, error) {
		loadCount++
		result := make(types.EntityMap)
		for _, uid := range uids {
			if uid == alice {
				result[uid] = types.Entity{UID: uid, Attributes: types.Record{}}
			}
		}
		return result, nil
	})

	caching := NewCachingEntityLoader(countingLoader)

	// First load
	result, _ := caching.Load(context.Background(), []types.EntityUID{alice})
	if loadCount != 1 {
		t.Errorf("expected 1 load, got %d", loadCount)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 entity, got %d", len(result))
	}

	// Second load - should be cached
	result, _ = caching.Load(context.Background(), []types.EntityUID{alice})
	if loadCount != 1 {
		t.Errorf("expected still 1 load (cached), got %d", loadCount)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 entity, got %d", len(result))
	}

	// Clear cache and load again
	caching.ClearCache()
	_, _ = caching.Load(context.Background(), []types.EntityUID{alice})
	if loadCount != 2 {
		t.Errorf("expected 2 loads after clear, got %d", loadCount)
	}

	// Test Cache() method
	cache := caching.Cache()
	if _, ok := cache[alice]; !ok {
		t.Error("expected alice in cache")
	}
}

func TestCachingEntityLoaderNotFound(t *testing.T) {
	alice := types.NewEntityUID("User", "alice")
	bob := types.NewEntityUID("User", "bob")
	loadCount := 0

	// Loader only returns alice, not bob
	loader := EntityLoaderFunc(func(ctx context.Context, uids []types.EntityUID) (types.EntityMap, error) {
		loadCount++
		result := make(types.EntityMap)
		for _, uid := range uids {
			if uid == alice {
				result[uid] = types.Entity{UID: uid}
			}
		}
		return result, nil
	})

	caching := NewCachingEntityLoader(loader)

	// Load bob (not found, should be cached as not found)
	result, _ := caching.Load(context.Background(), []types.EntityUID{bob})
	if len(result) != 0 {
		t.Errorf("expected 0 entities, got %d", len(result))
	}
	if loadCount != 1 {
		t.Errorf("expected 1 load, got %d", loadCount)
	}

	// Load bob again - should NOT call loader (cached as not found)
	result, _ = caching.Load(context.Background(), []types.EntityUID{bob})
	if len(result) != 0 {
		t.Errorf("expected 0 entities, got %d", len(result))
	}
	if loadCount != 1 {
		t.Errorf("expected still 1 load (not found cached), got %d", loadCount)
	}
}

func TestCachingEntityLoaderError(t *testing.T) {
	expectedErr := errors.New("load failed")
	loader := EntityLoaderFunc(func(ctx context.Context, uids []types.EntityUID) (types.EntityMap, error) {
		return nil, expectedErr
	})

	caching := NewCachingEntityLoader(loader)
	_, err := caching.Load(context.Background(), []types.EntityUID{types.NewEntityUID("User", "alice")})
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}

func TestTrackingEntityLoaderError(t *testing.T) {
	expectedErr := errors.New("load failed")
	loader := EntityLoaderFunc(func(ctx context.Context, uids []types.EntityUID) (types.EntityMap, error) {
		return nil, expectedErr
	})

	tracker := NewTrackingEntityLoader(loader)
	_, err := tracker.Load(context.Background(), []types.EntityUID{types.NewEntityUID("User", "alice")})
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}

func TestLoadingEntityGetterError(t *testing.T) {
	expectedErr := errors.New("load failed")
	loader := EntityLoaderFunc(func(ctx context.Context, uids []types.EntityUID) (types.EntityMap, error) {
		return nil, expectedErr
	})

	getter := NewLoadingEntityGetter(context.Background(), loader)
	_, ok := getter.Get(types.NewEntityUID("User", "alice"))
	if ok {
		t.Error("expected Get to fail due to error")
	}
}

func TestLoadingEntityGetter(t *testing.T) {
	alice := types.NewEntityUID("User", "alice")

	entities := types.EntityMap{
		alice: {UID: alice, Attributes: types.Record{}},
	}

	loader := NewMapEntityLoader(entities)
	getter := NewLoadingEntityGetter(context.Background(), loader)

	// Get existing entity
	entity, ok := getter.Get(alice)
	if !ok {
		t.Error("expected to find alice")
	}
	if entity.UID != alice {
		t.Errorf("expected alice UID, got %v", entity.UID)
	}

	// Get non-existent entity
	bob := types.NewEntityUID("User", "bob")
	_, ok = getter.Get(bob)
	if ok {
		t.Error("expected not to find bob")
	}
}

func TestEntityLoaderFunc(t *testing.T) {
	called := false
	loader := EntityLoaderFunc(func(ctx context.Context, uids []types.EntityUID) (types.EntityMap, error) {
		called = true
		return types.EntityMap{}, nil
	})

	_, _ = loader.Load(context.Background(), nil)
	if !called {
		t.Error("expected function to be called")
	}
}

func TestEntityLoaderError(t *testing.T) {
	expectedErr := errors.New("load failed")
	loader := EntityLoaderFunc(func(ctx context.Context, uids []types.EntityUID) (types.EntityMap, error) {
		return nil, expectedErr
	})

	_, err := loader.Load(context.Background(), nil)
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}

func TestCollectReferencedEntities(t *testing.T) {
	alice := types.NewEntityUID("User", "alice")
	doc := types.NewEntityUID("Doc", "readme")
	action := types.NewEntityUID("Action", "view")

	tests := []struct {
		name     string
		policy   *ast.Policy
		expected []types.EntityUID
	}{
		{
			name:     "nil policy",
			policy:   nil,
			expected: nil,
		},
		{
			name: "scope with entity",
			policy: &ast.Policy{
				Effect:    ast.EffectPermit,
				Principal: ast.ScopeTypeEq{Entity: alice},
				Action:    ast.ScopeTypeEq{Entity: action},
				Resource:  ast.ScopeTypeEq{Entity: doc},
			},
			expected: []types.EntityUID{alice, action, doc},
		},
		{
			name: "scope all",
			policy: &ast.Policy{
				Effect:    ast.EffectPermit,
				Principal: ast.ScopeTypeAll{},
				Action:    ast.ScopeTypeAll{},
				Resource:  ast.ScopeTypeAll{},
			},
			expected: []types.EntityUID{},
		},
		{
			name: "condition with entity literal",
			policy: &ast.Policy{
				Effect:    ast.EffectPermit,
				Principal: ast.ScopeTypeAll{},
				Action:    ast.ScopeTypeAll{},
				Resource:  ast.ScopeTypeAll{},
				Conditions: []ast.ConditionType{
					{
						Condition: ast.ConditionWhen,
						Body:      ast.NodeValue{Value: alice},
					},
				},
			},
			expected: []types.EntityUID{alice},
		},
		{
			name: "scope in",
			policy: &ast.Policy{
				Effect:    ast.EffectPermit,
				Principal: ast.ScopeTypeIn{Entity: alice},
				Action:    ast.ScopeTypeAll{},
				Resource:  ast.ScopeTypeAll{},
			},
			expected: []types.EntityUID{alice},
		},
		{
			name: "scope in set",
			policy: &ast.Policy{
				Effect:    ast.EffectPermit,
				Principal: ast.ScopeTypeAll{},
				Action:    ast.ScopeTypeInSet{Entities: []types.EntityUID{action, types.NewEntityUID("Action", "edit")}},
				Resource:  ast.ScopeTypeAll{},
			},
			expected: []types.EntityUID{action, types.NewEntityUID("Action", "edit")},
		},
		{
			name: "scope is in",
			policy: &ast.Policy{
				Effect:    ast.EffectPermit,
				Principal: ast.ScopeTypeIsIn{Type: "User", Entity: alice},
				Action:    ast.ScopeTypeAll{},
				Resource:  ast.ScopeTypeAll{},
			},
			expected: []types.EntityUID{alice},
		},
		{
			name: "condition with if-then-else",
			policy: &ast.Policy{
				Effect:    ast.EffectPermit,
				Principal: ast.ScopeTypeAll{},
				Action:    ast.ScopeTypeAll{},
				Resource:  ast.ScopeTypeAll{},
				Conditions: []ast.ConditionType{
					{
						Condition: ast.ConditionWhen,
						Body: ast.NodeTypeIfThenElse{
							If:   ast.NodeValue{Value: types.Boolean(true)},
							Then: ast.NodeValue{Value: alice},
							Else: ast.NodeValue{Value: doc},
						},
					},
				},
			},
			expected: []types.EntityUID{alice, doc},
		},
		{
			name: "condition with record",
			policy: &ast.Policy{
				Effect:    ast.EffectPermit,
				Principal: ast.ScopeTypeAll{},
				Action:    ast.ScopeTypeAll{},
				Resource:  ast.ScopeTypeAll{},
				Conditions: []ast.ConditionType{
					{
						Condition: ast.ConditionWhen,
						Body: ast.NodeTypeRecord{
							Elements: []ast.RecordElementNode{
								{Key: "owner", Value: ast.NodeValue{Value: alice}},
							},
						},
					},
				},
			},
			expected: []types.EntityUID{alice},
		},
		{
			name: "condition with set",
			policy: &ast.Policy{
				Effect:    ast.EffectPermit,
				Principal: ast.ScopeTypeAll{},
				Action:    ast.ScopeTypeAll{},
				Resource:  ast.ScopeTypeAll{},
				Conditions: []ast.ConditionType{
					{
						Condition: ast.ConditionWhen,
						Body: ast.NodeTypeSet{
							Elements: []ast.IsNode{
								ast.NodeValue{Value: alice},
								ast.NodeValue{Value: doc},
							},
						},
					},
				},
			},
			expected: []types.EntityUID{alice, doc},
		},
		{
			name: "condition with extension call",
			policy: &ast.Policy{
				Effect:    ast.EffectPermit,
				Principal: ast.ScopeTypeAll{},
				Action:    ast.ScopeTypeAll{},
				Resource:  ast.ScopeTypeAll{},
				Conditions: []ast.ConditionType{
					{
						Condition: ast.ConditionWhen,
						Body: ast.NodeTypeExtensionCall{
							Name: "test",
							Args: []ast.IsNode{
								ast.NodeValue{Value: alice},
							},
						},
					},
				},
			},
			expected: []types.EntityUID{alice},
		},
		{
			name: "value with record containing entity",
			policy: &ast.Policy{
				Effect:    ast.EffectPermit,
				Principal: ast.ScopeTypeAll{},
				Action:    ast.ScopeTypeAll{},
				Resource:  ast.ScopeTypeAll{},
				Conditions: []ast.ConditionType{
					{
						Condition: ast.ConditionWhen,
						Body: ast.NodeValue{Value: types.NewRecord(types.RecordMap{
							"owner": alice,
						})},
					},
				},
			},
			expected: []types.EntityUID{alice},
		},
		{
			name: "value with set containing entity",
			policy: &ast.Policy{
				Effect:    ast.EffectPermit,
				Principal: ast.ScopeTypeAll{},
				Action:    ast.ScopeTypeAll{},
				Resource:  ast.ScopeTypeAll{},
				Conditions: []ast.ConditionType{
					{
						Condition: ast.ConditionWhen,
						Body:      ast.NodeValue{Value: types.NewSet(alice, doc)},
					},
				},
			},
			expected: []types.EntityUID{alice, doc},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := CollectReferencedEntities(tc.policy)

			if len(result) != len(tc.expected) {
				t.Errorf("expected %d entities, got %d", len(tc.expected), len(result))
				return
			}

			// Check all expected entities are present
			for _, expected := range tc.expected {
				if !slices.Contains(result, expected) {
					t.Errorf("expected entity %v not found in result", expected)
				}
			}
		})
	}
}
