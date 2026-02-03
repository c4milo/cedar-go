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
	"slices"
	"testing"

	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
)

// queryResultAsserter helps verify QueryResult fields.
type queryResultAsserter struct {
	t      *testing.T
	result *QueryResult
}

func assertQueryResult(t *testing.T, result *QueryResult) *queryResultAsserter {
	return &queryResultAsserter{t: t, result: result}
}

func (a *queryResultAsserter) decision(want types.Decision) *queryResultAsserter {
	a.t.Helper()
	if a.result.Decision != want {
		a.t.Errorf("Decision = %v, want %v", a.result.Decision, want)
	}
	return a
}

func (a *queryResultAsserter) all(want bool) *queryResultAsserter {
	a.t.Helper()
	if a.result.All != want {
		a.t.Errorf("All = %v, want %v", a.result.All, want)
	}
	return a
}

func (a *queryResultAsserter) definite(want bool) *queryResultAsserter {
	a.t.Helper()
	if a.result.Definite != want {
		a.t.Errorf("Definite = %v, want %v", a.result.Definite, want)
	}
	return a
}

func (a *queryResultAsserter) valuesCount(want int) *queryResultAsserter {
	a.t.Helper()
	if len(a.result.SatisfyingValues) != want {
		a.t.Errorf("SatisfyingValues count = %d, want %d", len(a.result.SatisfyingValues), want)
	}
	return a
}

func (a *queryResultAsserter) hasValue(want types.EntityUID) *queryResultAsserter {
	a.t.Helper()
	if !slices.Contains(a.result.SatisfyingValues, want) {
		a.t.Errorf("Missing expected value: %v", want)
	}
	return a
}

func (a *queryResultAsserter) constraintsCount(want int) *queryResultAsserter {
	a.t.Helper()
	if len(a.result.Constraints) != want {
		a.t.Errorf("Constraints count = %d, want %d", len(a.result.Constraints), want)
	}
	return a
}

// queryDecisionAsserter helps verify QueryDecisionResult fields.
type queryDecisionAsserter struct {
	t      *testing.T
	result *QueryDecisionResult
}

func assertQueryDecision(t *testing.T, result *QueryDecisionResult) *queryDecisionAsserter {
	return &queryDecisionAsserter{t: t, result: result}
}

func (a *queryDecisionAsserter) decision(want types.Decision) *queryDecisionAsserter {
	a.t.Helper()
	if a.result.Decision != want {
		a.t.Errorf("Decision = %v, want %v", a.result.Decision, want)
	}
	return a
}

func (a *queryDecisionAsserter) hasDetermining(want types.PolicyID) *queryDecisionAsserter {
	a.t.Helper()
	if !slices.Contains(a.result.DeterminingPolicies, want) {
		a.t.Errorf("Missing determining policy: %v", want)
	}
	return a
}

func (a *queryDecisionAsserter) erroringCount(want int) *queryDecisionAsserter {
	a.t.Helper()
	if len(a.result.ErroringPolicies) != want {
		a.t.Errorf("ErroringPolicies count = %d, want %d", len(a.result.ErroringPolicies), want)
	}
	return a
}

func TestQueryPrincipals(t *testing.T) {
	tests := []struct {
		name            string
		policies        map[types.PolicyID]*ast.Policy
		entities        types.EntityMap
		action          types.EntityUID
		resource        types.EntityUID
		wantDecision    types.Decision
		wantAll         bool
		wantDefinite    bool
		wantValues      []types.EntityUID
		wantConstraints int
	}{
		{
			name: "permit all principals",
			policies: map[types.PolicyID]*ast.Policy{
				"policy1": ast.Permit(),
			},
			action:       types.NewEntityUID("Action", "read"),
			resource:     types.NewEntityUID("Document", "doc1"),
			wantDecision: types.Allow,
			wantAll:      true,
			wantDefinite: true,
		},
		{
			name: "permit specific principal",
			policies: map[types.PolicyID]*ast.Policy{
				"policy1": ast.Permit().
					PrincipalEq(types.NewEntityUID("User", "alice")),
			},
			action:       types.NewEntityUID("Action", "read"),
			resource:     types.NewEntityUID("Document", "doc1"),
			wantDecision: types.Allow,
			wantDefinite: true,
			wantValues:   []types.EntityUID{types.NewEntityUID("User", "alice")},
		},
		{
			name: "permit principal in group with constraint",
			policies: map[types.PolicyID]*ast.Policy{
				"policy1": ast.Permit().
					PrincipalIn(types.NewEntityUID("Group", "admins")),
			},
			action:          types.NewEntityUID("Action", "read"),
			resource:        types.NewEntityUID("Document", "doc1"),
			wantDecision:    types.Deny, // No specific values extracted
			wantDefinite:    false,      // Not definite because we have unresolved constraints
			wantConstraints: 1,          // Has an "in" constraint
		},
		{
			name: "forbid all - deny",
			policies: map[types.PolicyID]*ast.Policy{
				"policy1": ast.Permit(),
				"policy2": ast.Forbid(),
			},
			action:       types.NewEntityUID("Action", "delete"),
			resource:     types.NewEntityUID("Document", "doc1"),
			wantDecision: types.Deny,
			wantAll:      false,
			wantDefinite: true,
		},
		{
			name:         "no policies - deny",
			policies:     map[types.PolicyID]*ast.Policy{},
			action:       types.NewEntityUID("Action", "read"),
			resource:     types.NewEntityUID("Document", "doc1"),
			wantDecision: types.Deny,
			wantDefinite: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := QueryPrincipals(tc.policies, tc.entities, tc.action, tc.resource, types.Record{})
			a := assertQueryResult(t, result).decision(tc.wantDecision).all(tc.wantAll).definite(tc.wantDefinite)
			if len(tc.wantValues) > 0 {
				a.valuesCount(len(tc.wantValues))
				for _, v := range tc.wantValues {
					a.hasValue(v)
				}
			}
			if tc.wantConstraints > 0 {
				a.constraintsCount(tc.wantConstraints)
			}
		})
	}
}

func TestQueryResources(t *testing.T) {
	tests := []struct {
		name         string
		policies     map[types.PolicyID]*ast.Policy
		entities     types.EntityMap
		principal    types.EntityUID
		action       types.EntityUID
		wantDecision types.Decision
		wantAll      bool
		wantDefinite bool
		wantValues   []types.EntityUID
	}{
		{
			name: "permit all resources",
			policies: map[types.PolicyID]*ast.Policy{
				"policy1": ast.Permit().
					PrincipalEq(types.NewEntityUID("User", "alice")),
			},
			principal:    types.NewEntityUID("User", "alice"),
			action:       types.NewEntityUID("Action", "read"),
			wantDecision: types.Allow,
			wantAll:      true,
			wantDefinite: true,
		},
		{
			name: "permit specific resource",
			policies: map[types.PolicyID]*ast.Policy{
				"policy1": ast.Permit().
					ResourceEq(types.NewEntityUID("Document", "public.txt")),
			},
			principal:    types.NewEntityUID("User", "alice"),
			action:       types.NewEntityUID("Action", "read"),
			wantDecision: types.Allow,
			wantDefinite: true,
			wantValues:   []types.EntityUID{types.NewEntityUID("Document", "public.txt")},
		},
		{
			name: "principal doesn't match - deny all resources",
			policies: map[types.PolicyID]*ast.Policy{
				"policy1": ast.Permit().
					PrincipalEq(types.NewEntityUID("User", "bob")),
			},
			principal:    types.NewEntityUID("User", "alice"),
			action:       types.NewEntityUID("Action", "read"),
			wantDecision: types.Deny,
			wantDefinite: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := QueryResources(tc.policies, tc.entities, tc.principal, tc.action, types.Record{})
			a := assertQueryResult(t, result).decision(tc.wantDecision).all(tc.wantAll).definite(tc.wantDefinite)
			if len(tc.wantValues) > 0 {
				a.valuesCount(len(tc.wantValues))
			}
		})
	}
}

func TestQueryActions(t *testing.T) {
	tests := []struct {
		name         string
		policies     map[types.PolicyID]*ast.Policy
		entities     types.EntityMap
		principal    types.EntityUID
		resource     types.EntityUID
		wantDecision types.Decision
		wantAll      bool
		wantDefinite bool
		wantValues   []types.EntityUID
	}{
		{
			name: "permit all actions",
			policies: map[types.PolicyID]*ast.Policy{
				"policy1": ast.Permit().
					PrincipalEq(types.NewEntityUID("User", "admin")),
			},
			principal:    types.NewEntityUID("User", "admin"),
			resource:     types.NewEntityUID("Document", "doc1"),
			wantDecision: types.Allow,
			wantAll:      true,
			wantDefinite: true,
		},
		{
			name: "permit specific action",
			policies: map[types.PolicyID]*ast.Policy{
				"policy1": ast.Permit().
					ActionEq(types.NewEntityUID("Action", "view")),
			},
			principal:    types.NewEntityUID("User", "alice"),
			resource:     types.NewEntityUID("Document", "doc1"),
			wantDecision: types.Allow,
			wantDefinite: true,
			wantValues:   []types.EntityUID{types.NewEntityUID("Action", "view")},
		},
		{
			name: "permit multiple actions",
			policies: map[types.PolicyID]*ast.Policy{
				"policy1": ast.Permit().
					ActionInSet(
						types.NewEntityUID("Action", "read"),
						types.NewEntityUID("Action", "list"),
					),
			},
			principal:    types.NewEntityUID("User", "alice"),
			resource:     types.NewEntityUID("Document", "doc1"),
			wantDecision: types.Allow,
			wantDefinite: true,
			wantValues: []types.EntityUID{
				types.NewEntityUID("Action", "read"),
				types.NewEntityUID("Action", "list"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := QueryActions(tc.policies, tc.entities, tc.principal, tc.resource, types.Record{})
			a := assertQueryResult(t, result).decision(tc.wantDecision).all(tc.wantAll).definite(tc.wantDefinite)
			if len(tc.wantValues) > 0 {
				a.valuesCount(len(tc.wantValues))
				for _, v := range tc.wantValues {
					a.hasValue(v)
				}
			}
		})
	}
}

func TestQueryDecision(t *testing.T) {
	tests := []struct {
		name              string
		policies          map[types.PolicyID]*ast.Policy
		entities          types.EntityMap
		principal         types.EntityUID
		action            types.EntityUID
		resource          types.EntityUID
		wantDecision      types.Decision
		wantDetermining   []types.PolicyID
		wantErroringCount int
	}{
		{
			name: "simple permit",
			policies: map[types.PolicyID]*ast.Policy{
				"policy1": ast.Permit(),
			},
			principal:       types.NewEntityUID("User", "alice"),
			action:          types.NewEntityUID("Action", "read"),
			resource:        types.NewEntityUID("Document", "doc1"),
			wantDecision:    types.Allow,
			wantDetermining: []types.PolicyID{"policy1"},
		},
		{
			name: "forbid trumps permit",
			policies: map[types.PolicyID]*ast.Policy{
				"permit1": ast.Permit(),
				"forbid1": ast.Forbid(),
			},
			principal:       types.NewEntityUID("User", "alice"),
			action:          types.NewEntityUID("Action", "read"),
			resource:        types.NewEntityUID("Document", "doc1"),
			wantDecision:    types.Deny,
			wantDetermining: []types.PolicyID{"forbid1"},
		},
		{
			name: "multiple determining permits",
			policies: map[types.PolicyID]*ast.Policy{
				"permit1": ast.Permit().PrincipalEq(types.NewEntityUID("User", "alice")),
				"permit2": ast.Permit().ResourceEq(types.NewEntityUID("Document", "doc1")),
			},
			principal:       types.NewEntityUID("User", "alice"),
			action:          types.NewEntityUID("Action", "read"),
			resource:        types.NewEntityUID("Document", "doc1"),
			wantDecision:    types.Allow,
			wantDetermining: []types.PolicyID{"permit1", "permit2"},
		},
		{
			name:         "no policies - deny",
			policies:     map[types.PolicyID]*ast.Policy{},
			principal:    types.NewEntityUID("User", "alice"),
			action:       types.NewEntityUID("Action", "read"),
			resource:     types.NewEntityUID("Document", "doc1"),
			wantDecision: types.Deny,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := QueryDecision(tc.policies, tc.entities, tc.principal, tc.action, tc.resource, types.Record{})
			a := assertQueryDecision(t, result).decision(tc.wantDecision)
			for _, want := range tc.wantDetermining {
				a.hasDetermining(want)
			}
			if tc.wantErroringCount > 0 {
				a.erroringCount(tc.wantErroringCount)
			}
		})
	}
}

func TestConstraintKindString(t *testing.T) {
	tests := []struct {
		kind ConstraintKind
		want string
	}{
		{ConstraintEq, "0"},
		{ConstraintIn, "1"},
		{ConstraintIs, "2"},
		{ConstraintIsIn, "3"},
		{ConstraintInSet, "4"},
	}

	for _, tc := range tests {
		// ConstraintKind is an int, just verify the enum values
		if int(tc.kind) < 0 || int(tc.kind) > 4 {
			t.Errorf("Invalid ConstraintKind value: %d", tc.kind)
		}
	}
}

func TestQueryPrincipalsWithIsConstraint(t *testing.T) {
	policies := map[types.PolicyID]*ast.Policy{
		"policy1": ast.Permit().PrincipalIs("User"),
	}

	result := QueryPrincipals(
		policies,
		nil,
		types.NewEntityUID("Action", "read"),
		types.NewEntityUID("Document", "doc1"),
		types.Record{},
	)

	// Should have Is constraint
	hasIsConstraint := false
	for _, c := range result.Constraints {
		if c.Kind == ConstraintIs {
			hasIsConstraint = true
		}
	}
	if !hasIsConstraint {
		t.Error("Expected Is constraint")
	}
}

func TestQueryPrincipalsWithIsInConstraint(t *testing.T) {
	policies := map[types.PolicyID]*ast.Policy{
		"policy1": ast.Permit().PrincipalIsIn("User", types.NewEntityUID("Group", "admins")),
	}

	result := QueryPrincipals(
		policies,
		nil,
		types.NewEntityUID("Action", "read"),
		types.NewEntityUID("Document", "doc1"),
		types.Record{},
	)

	// Should have IsIn constraint
	hasIsInConstraint := false
	for _, c := range result.Constraints {
		if c.Kind == ConstraintIsIn {
			hasIsInConstraint = true
		}
	}
	if !hasIsInConstraint {
		t.Error("Expected IsIn constraint")
	}
}

func TestQueryActionsWithInSetConstraint(t *testing.T) {
	policies := map[types.PolicyID]*ast.Policy{
		"policy1": ast.Permit().ActionInSet(
			types.NewEntityUID("Action", "read"),
			types.NewEntityUID("Action", "write"),
		),
	}

	result := QueryActions(
		policies,
		nil,
		types.NewEntityUID("User", "alice"),
		types.NewEntityUID("Document", "doc1"),
		types.Record{},
	)

	// Should have InSet constraint
	hasInSetConstraint := false
	for _, c := range result.Constraints {
		if c.Kind == ConstraintInSet {
			hasInSetConstraint = true
		}
	}
	if !hasInSetConstraint {
		t.Error("Expected InSet constraint")
	}
}

func TestQueryActionsWithInConstraint(t *testing.T) {
	policies := map[types.PolicyID]*ast.Policy{
		"policy1": ast.Permit().ActionIn(types.NewEntityUID("ActionGroup", "readActions")),
	}

	result := QueryActions(
		policies,
		nil,
		types.NewEntityUID("User", "alice"),
		types.NewEntityUID("Document", "doc1"),
		types.Record{},
	)

	// Should have In constraint
	hasInConstraint := false
	for _, c := range result.Constraints {
		if c.Kind == ConstraintIn {
			hasInConstraint = true
		}
	}
	if !hasInConstraint {
		t.Error("Expected In constraint")
	}
}

func TestQueryDecisionWithErroringPolicy(t *testing.T) {
	// Create a policy with an error condition (comparing incompatible types)
	policies := map[types.PolicyID]*ast.Policy{
		"error_policy": ast.Permit().When(ast.Long(1).GreaterThan(ast.String("not a number"))),
	}

	result := QueryDecision(
		policies,
		nil,
		types.NewEntityUID("User", "alice"),
		types.NewEntityUID("Action", "read"),
		types.NewEntityUID("Document", "doc1"),
		types.Record{},
	)

	if len(result.ErroringPolicies) == 0 {
		t.Error("Expected erroring policies")
	}
}

func TestQueryWithVariableForbid(t *testing.T) {
	// Forbid policy with variable principal - can't be certain
	policies := map[types.PolicyID]*ast.Policy{
		"permit": ast.Permit(),
		"forbid": ast.Forbid().PrincipalIn(types.NewEntityUID("Group", "banned")),
	}

	result := QueryPrincipals(
		policies,
		nil,
		types.NewEntityUID("Action", "read"),
		types.NewEntityUID("Document", "doc1"),
		types.Record{},
	)

	// Should not be definite because forbid has variable
	if result.Definite {
		t.Error("Expected indefinite result due to variable forbid")
	}
}

func TestQueryDecisionWithErroringForbid(t *testing.T) {
	// Forbid policy with an error condition
	policies := map[types.PolicyID]*ast.Policy{
		"permit":       ast.Permit(),
		"error_forbid": ast.Forbid().When(ast.Long(1).GreaterThan(ast.String("not a number"))),
	}

	result := QueryDecision(
		policies,
		nil,
		types.NewEntityUID("User", "alice"),
		types.NewEntityUID("Action", "read"),
		types.NewEntityUID("Document", "doc1"),
		types.Record{},
	)

	if len(result.ErroringPolicies) == 0 {
		t.Error("Expected erroring policies")
	}
}

func TestQueryPrincipalsWithScopeAll(t *testing.T) {
	// Policy with scope all (permit all)
	policies := map[types.PolicyID]*ast.Policy{
		"permit_all": ast.Permit(),
	}

	result := QueryPrincipals(
		policies,
		nil,
		types.NewEntityUID("Action", "read"),
		types.NewEntityUID("Document", "doc1"),
		types.Record{},
	)

	if result.Decision != types.Allow {
		t.Error("Expected allow for permit all")
	}
	if !result.All {
		t.Error("Expected All to be true for permit all")
	}
}

func TestQueryActionsWithScopeAll(t *testing.T) {
	// Policy with action scope all
	policies := map[types.PolicyID]*ast.Policy{
		"permit": ast.Permit(),
	}

	result := QueryActions(
		policies,
		nil,
		types.NewEntityUID("User", "alice"),
		types.NewEntityUID("Document", "doc1"),
		types.Record{},
	)

	if result.Decision != types.Allow {
		t.Error("Expected allow")
	}
	if !result.All {
		t.Error("Expected All to be true for action scope all")
	}
}

func TestQueryWithNilPolicy(t *testing.T) {
	// Test extractPolicyConstraints with nil policy
	constraints := extractPolicyConstraints(nil, "principal")
	if constraints != nil {
		t.Error("Expected nil constraints for nil policy")
	}

	// Test extractScopeValues with nil policy
	values := extractScopeValues(nil, "principal")
	if values != nil {
		t.Error("Expected nil values for nil policy")
	}
}

func TestCollectReferencedEntitiesWithNilNode(t *testing.T) {
	// Test nil node handling in collectNodeEntities
	var uids []types.EntityUID
	seen := make(map[types.EntityUID]struct{})
	collectNodeEntities(&uids, &seen, nil)
	if len(uids) != 0 {
		t.Error("Expected empty result for nil node")
	}
}

func TestExtractScopeConstraintsAll(t *testing.T) {
	// Test ScopeTypeAll returns nil
	constraints := extractScopeConstraints(ast.ScopeTypeAll{})
	if constraints != nil {
		t.Error("Expected nil for ScopeTypeAll")
	}
}

func TestExtractScopeConstraintsInSet(t *testing.T) {
	// Test ScopeTypeInSet (not handled, should return nil via default)
	entities := []types.EntityUID{
		types.NewEntityUID("User", "alice"),
		types.NewEntityUID("User", "bob"),
	}
	constraints := extractScopeConstraints(ast.ScopeTypeInSet{Entities: entities})
	// ScopeTypeInSet falls through to default case for principal/resource scope
	if constraints != nil {
		t.Error("Expected nil for unhandled scope type")
	}
}

func TestExtractActionScopeConstraintsAll(t *testing.T) {
	// Test ScopeTypeAll returns nil for action scope
	constraints := extractActionScopeConstraints(ast.ScopeTypeAll{})
	if constraints != nil {
		t.Error("Expected nil for ScopeTypeAll")
	}
}

func TestExtractActionScopeConstraintsUnhandled(t *testing.T) {
	// Test unhandled action scope type (should return nil via default)
	// ScopeTypeIs is not typically used for actions
	constraints := extractActionScopeConstraints(ast.ScopeTypeIs{Type: "Action"})
	if constraints != nil {
		t.Error("Expected nil for unhandled action scope type")
	}
}

// UI Permission Checking Tests - demonstrate common use cases for QueryActions

func TestQueryActionsUIButtonVisibility(t *testing.T) {
	// Scenario: Determine which action buttons to show in a document viewer UI
	// based on the user's group membership

	// Create entities with group membership
	entities := types.EntityMap{
		types.NewEntityUID("User", "alice"): types.Entity{
			UID: types.NewEntityUID("User", "alice"),
			Parents: types.NewEntityUIDSet(
				types.NewEntityUID("Group", "viewers"),
			),
		},
		types.NewEntityUID("User", "bob"): types.Entity{
			UID: types.NewEntityUID("User", "bob"),
			Parents: types.NewEntityUIDSet(
				types.NewEntityUID("Group", "viewers"),
				types.NewEntityUID("Group", "editors"),
			),
		},
		types.NewEntityUID("User", "admin"): types.Entity{
			UID: types.NewEntityUID("User", "admin"),
			Parents: types.NewEntityUIDSet(
				types.NewEntityUID("Group", "admins"),
			),
		},
		types.NewEntityUID("Group", "viewers"): types.Entity{
			UID: types.NewEntityUID("Group", "viewers"),
		},
		types.NewEntityUID("Group", "editors"): types.Entity{
			UID: types.NewEntityUID("Group", "editors"),
		},
		types.NewEntityUID("Group", "admins"): types.Entity{
			UID: types.NewEntityUID("Group", "admins"),
		},
		types.NewEntityUID("Document", "report.pdf"): types.Entity{
			UID: types.NewEntityUID("Document", "report.pdf"),
		},
	}

	// Define policies for different roles
	policies := map[types.PolicyID]*ast.Policy{
		"viewers_can_view": ast.Permit().
			PrincipalIn(types.NewEntityUID("Group", "viewers")).
			ActionEq(types.NewEntityUID("Action", "view")),
		"editors_can_edit": ast.Permit().
			PrincipalIn(types.NewEntityUID("Group", "editors")).
			ActionInSet(
				types.NewEntityUID("Action", "view"),
				types.NewEntityUID("Action", "edit"),
			),
		"admins_can_all": ast.Permit().
			PrincipalIn(types.NewEntityUID("Group", "admins")),
	}

	resource := types.NewEntityUID("Document", "report.pdf")

	// Test alice (viewer only) - should only see view
	aliceResult := QueryActions(
		policies,
		entities,
		types.NewEntityUID("User", "alice"),
		resource,
		types.Record{},
	)
	if aliceResult.Decision != types.Allow {
		t.Error("Expected alice to have some permissions")
	}
	if aliceResult.All {
		t.Error("Expected alice to NOT have all permissions")
	}
	aliceActions := make(map[string]bool)
	for _, action := range aliceResult.SatisfyingValues {
		aliceActions[string(action.ID)] = true
	}
	if !aliceActions["view"] {
		t.Error("Expected alice to have view action")
	}

	// Test bob (viewer + editor) - should see view and edit
	bobResult := QueryActions(
		policies,
		entities,
		types.NewEntityUID("User", "bob"),
		resource,
		types.Record{},
	)
	if bobResult.Decision != types.Allow {
		t.Error("Expected bob to have some permissions")
	}
	bobActions := make(map[string]bool)
	for _, action := range bobResult.SatisfyingValues {
		bobActions[string(action.ID)] = true
	}
	if !bobActions["view"] {
		t.Error("Expected bob to have view action")
	}
	if !bobActions["edit"] {
		t.Error("Expected bob to have edit action")
	}

	// Test admin - should have all actions
	adminResult := QueryActions(
		policies,
		entities,
		types.NewEntityUID("User", "admin"),
		resource,
		types.Record{},
	)
	if adminResult.Decision != types.Allow {
		t.Error("Expected admin to have permissions")
	}
	if !adminResult.All {
		t.Error("Expected admin to have ALL permissions")
	}
}

func TestQueryActionsWithForbidPolicy(t *testing.T) {
	// Scenario: Admin has all permissions except delete on archived documents

	entities := types.EntityMap{
		types.NewEntityUID("User", "admin"): types.Entity{
			UID: types.NewEntityUID("User", "admin"),
			Parents: types.NewEntityUIDSet(
				types.NewEntityUID("Group", "admins"),
			),
		},
		types.NewEntityUID("Group", "admins"): types.Entity{
			UID: types.NewEntityUID("Group", "admins"),
		},
		types.NewEntityUID("Document", "archived.pdf"): types.Entity{
			UID: types.NewEntityUID("Document", "archived.pdf"),
			Parents: types.NewEntityUIDSet(
				types.NewEntityUID("Folder", "archive"),
			),
		},
		types.NewEntityUID("Folder", "archive"): types.Entity{
			UID: types.NewEntityUID("Folder", "archive"),
		},
	}

	policies := map[types.PolicyID]*ast.Policy{
		"admins_can_all": ast.Permit().
			PrincipalIn(types.NewEntityUID("Group", "admins")),
		"no_delete_archived": ast.Forbid().
			ActionEq(types.NewEntityUID("Action", "delete")).
			ResourceIn(types.NewEntityUID("Folder", "archive")),
	}

	result := QueryActions(
		policies,
		entities,
		types.NewEntityUID("User", "admin"),
		types.NewEntityUID("Document", "archived.pdf"),
		types.Record{},
	)

	// With forbid policy that has variable action, result should be indefinite
	// because we can't be certain about all actions
	if result.Definite && result.All {
		t.Error("Expected result to not be both definite and all due to forbid policy")
	}
}

func TestQueryPrincipalsAccessControlList(t *testing.T) {
	// Scenario: Build an access control list showing who can access a resource

	entities := types.EntityMap{
		types.NewEntityUID("Document", "secret.pdf"): types.Entity{
			UID: types.NewEntityUID("Document", "secret.pdf"),
		},
	}

	policies := map[types.PolicyID]*ast.Policy{
		"alice_can_read": ast.Permit().
			PrincipalEq(types.NewEntityUID("User", "alice")).
			ActionEq(types.NewEntityUID("Action", "read")),
		"bob_can_read": ast.Permit().
			PrincipalEq(types.NewEntityUID("User", "bob")).
			ActionEq(types.NewEntityUID("Action", "read")),
		"charlie_can_read": ast.Permit().
			PrincipalEq(types.NewEntityUID("User", "charlie")).
			ActionEq(types.NewEntityUID("Action", "read")),
	}

	result := QueryPrincipals(
		policies,
		entities,
		types.NewEntityUID("Action", "read"),
		types.NewEntityUID("Document", "secret.pdf"),
		types.Record{},
	)

	if result.Decision != types.Allow {
		t.Error("Expected allow decision")
	}
	if len(result.SatisfyingValues) != 3 {
		t.Errorf("Expected 3 principals, got %d", len(result.SatisfyingValues))
	}

	// Verify all expected users are in the result
	expectedUsers := map[string]bool{
		"alice":   false,
		"bob":     false,
		"charlie": false,
	}
	for _, uid := range result.SatisfyingValues {
		if uid.Type == "User" {
			expectedUsers[string(uid.ID)] = true
		}
	}
	for user, found := range expectedUsers {
		if !found {
			t.Errorf("Expected user %s in results", user)
		}
	}
}

func TestQueryResourcesFileExplorer(t *testing.T) {
	// Scenario: Show which resources a user can access in a file explorer

	policies := map[types.PolicyID]*ast.Policy{
		"alice_public": ast.Permit().
			PrincipalEq(types.NewEntityUID("User", "alice")).
			ResourceEq(types.NewEntityUID("Document", "public.txt")),
		"alice_shared": ast.Permit().
			PrincipalEq(types.NewEntityUID("User", "alice")).
			ResourceEq(types.NewEntityUID("Document", "shared.txt")),
	}

	result := QueryResources(
		policies,
		nil,
		types.NewEntityUID("User", "alice"),
		types.NewEntityUID("Action", "read"),
		types.Record{},
	)

	if result.Decision != types.Allow {
		t.Error("Expected allow decision")
	}
	if len(result.SatisfyingValues) != 2 {
		t.Errorf("Expected 2 resources, got %d", len(result.SatisfyingValues))
	}
}

func TestQueryDecisionAuditLog(t *testing.T) {
	// Scenario: Detailed audit logging showing which policies allowed/denied access

	policies := map[types.PolicyID]*ast.Policy{
		"base_permit": ast.Permit().
			PrincipalIn(types.NewEntityUID("Group", "employees")),
		"sensitive_forbid": ast.Forbid().
			ResourceIn(types.NewEntityUID("Folder", "sensitive")).
			When(ast.Not(ast.Principal().Is("Manager"))),
	}

	entities := types.EntityMap{
		types.NewEntityUID("User", "employee"): types.Entity{
			UID: types.NewEntityUID("User", "employee"),
			Parents: types.NewEntityUIDSet(
				types.NewEntityUID("Group", "employees"),
			),
		},
		types.NewEntityUID("Group", "employees"): types.Entity{
			UID: types.NewEntityUID("Group", "employees"),
		},
		types.NewEntityUID("Document", "report.pdf"): types.Entity{
			UID: types.NewEntityUID("Document", "report.pdf"),
		},
	}

	result := QueryDecision(
		policies,
		entities,
		types.NewEntityUID("User", "employee"),
		types.NewEntityUID("Action", "read"),
		types.NewEntityUID("Document", "report.pdf"),
		types.Record{},
	)

	if result.Decision != types.Allow {
		t.Error("Expected allow for non-sensitive document")
	}
	if len(result.DeterminingPolicies) == 0 {
		t.Error("Expected at least one determining policy")
	}
}
