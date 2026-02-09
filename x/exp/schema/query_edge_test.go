package schema

import (
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// --- Introspect: Validator-facing map accessors ---

// The Map accessors expose internal state to the validator package.
// Verify they return populated, consistent views.
func TestIntrospectMaps(t *testing.T) {
	src := `{
		"commonTypes": {"Email": {"type": "String"}},
		"entityTypes": {
			"User": {
				"shape": {"type": "Record", "attributes": {"email": {"type": "Email"}}}
			},
			"Document": {}
		},
		"actions": {
			"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Document"]}}
		}
	}`
	s, err := NewFromJSON([]byte(src))
	if err != nil {
		t.Fatal(err)
	}

	// EntityTypesMap should expose parsed entity info
	etm := s.EntityTypesMap()
	if len(etm) != 2 {
		t.Errorf("EntityTypesMap: got %d types, want 2", len(etm))
	}
	userInfo := etm["User"]
	if userInfo == nil {
		t.Fatal("EntityTypesMap missing User")
	}
	if _, ok := userInfo.Attributes["email"]; !ok {
		t.Error("User should have 'email' attribute from common type")
	}

	// ActionTypesMap should expose parsed action info
	atm := s.ActionTypesMap()
	if len(atm) != 1 {
		t.Errorf("ActionTypesMap: got %d actions, want 1", len(atm))
	}

	// CommonTypesMap should expose parsed common types
	ctm := s.CommonTypesMap()
	if _, ok := ctm["Email"]; !ok {
		t.Error("CommonTypesMap missing Email")
	}
}

// --- Iterator early termination ---

// Iterators backed by maps/slices must respect yield returning false.
// A bug here can cause unexpected behavior when callers use break/return.
func TestIteratorEarlyTermination(t *testing.T) {
	s := newTestSchema(t)

	takeFirst := func(name string, count int) {
		t.Helper()
		if count != 1 {
			t.Errorf("%s: expected 1 after break, got %d", name, count)
		}
	}

	// All iterators: break after first element
	c := 0
	for range s.EntityTypes() {
		c++
		break
	}
	takeFirst("EntityTypes", c)

	c = 0
	for range s.Actions() {
		c++
		break
	}
	takeFirst("Actions", c)

	c = 0
	for range s.ActionGroups() {
		c++
		break
	}
	takeFirst("ActionGroups", c)

	c = 0
	for range s.Principals() {
		c++
		break
	}
	takeFirst("Principals", c)

	c = 0
	for range s.Resources() {
		c++
		break
	}
	takeFirst("Resources", c)

	c = 0
	for range s.RequestEnvs() {
		c++
		break
	}
	takeFirst("RequestEnvs", c)

	// Conditional iterators
	iter, ok := s.PrincipalsForAction(types.EntityUID{Type: "MyApp::Action", ID: "view"})
	if !ok {
		t.Fatal("PrincipalsForAction returned false")
	}
	c = 0
	for range iter {
		c++
		break
	}
	takeFirst("PrincipalsForAction", c)

	iterR, ok := s.ResourcesForAction(types.EntityUID{Type: "MyApp::Action", ID: "edit"})
	if !ok {
		t.Fatal("ResourcesForAction returned false")
	}
	c = 0
	for range iterR {
		c++
		break
	}
	takeFirst("ResourcesForAction", c)

	ancestorIter, _ := s.Ancestors("MyApp::User")
	c = 0
	for range ancestorIter {
		c++
		break
	}
	takeFirst("Ancestors", c)

	c = 0
	for range s.ActionsForPrincipalAndResource("MyApp::User", "MyApp::Document") {
		c++
		break
	}
	takeFirst("ActionsForPrincipalAndResource", c)
}

// --- Query API: Input validation ---

// QueryResource must reject requests where the principal type isn't
// in the action's appliesTo.principalTypes.
func TestQueryResourceRejectsBadPrincipalType(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()
	ps := mustPolicies(t, `permit (principal, action, resource);`)

	_, err := s.QueryResource(ps, entities, ResourceQueryRequest{
		Principal:    types.NewEntityUID("MyApp::Document", "doc1"), // Document isn't a principal
		Action:       types.NewEntityUID("MyApp::Action", "view"),
		ResourceType: "MyApp::Document",
		Context:      types.NewRecord(nil),
	})
	if err == nil {
		t.Error("expected error: Document is not a valid principal type for 'view'")
	}
	if !strings.Contains(err.Error(), "principal type") {
		t.Errorf("error should mention principal type, got: %v", err)
	}
}

// QueryResource must reject requests where the resource type isn't
// in the action's appliesTo.resourceTypes.
func TestQueryResourceRejectsBadResourceType(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()
	ps := mustPolicies(t, `permit (principal, action, resource);`)

	_, err := s.QueryResource(ps, entities, ResourceQueryRequest{
		Principal:    types.NewEntityUID("MyApp::User", "alice"),
		Action:       types.NewEntityUID("MyApp::Action", "edit"),
		ResourceType: "MyApp::User", // User isn't a resource type for edit
		Context:      types.NewRecord(nil),
	})
	if err == nil {
		t.Error("expected error: User is not a valid resource type for 'edit'")
	}
	if !strings.Contains(err.Error(), "resource type") {
		t.Errorf("error should mention resource type, got: %v", err)
	}
}

// QueryPrincipal must reject requests where the resource type doesn't match.
func TestQueryPrincipalRejectsBadResourceType(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()
	ps := mustPolicies(t, `permit (principal, action, resource);`)

	_, err := s.QueryPrincipal(ps, entities, PrincipalQueryRequest{
		PrincipalType: "MyApp::User",
		Action:        types.NewEntityUID("MyApp::Action", "edit"),
		Resource:      types.NewEntityUID("MyApp::User", "alice"), // User isn't a resource
		Context:       types.NewRecord(nil),
	})
	if err == nil {
		t.Error("expected error: User is not a valid resource type for 'edit'")
	}
}

// --- Query Diff: Permission change detection ---

// When a policy is added that creates a new deny for an action that
// wasn't in the base results, it should appear as Unchanged (not Lost,
// since it was never allowed).
func TestDiffResultsNewDeniedActionIsUnchanged(t *testing.T) {
	base := []QueryResult{} // action wasn't in base
	updated := []QueryResult{
		{Entity: types.NewEntityUID("Action", "view"), Decision: types.Deny},
	}
	diff := diffResults(base, updated)
	if len(diff.Gained) != 0 {
		t.Errorf("new denied action should not be Gained, got %d", len(diff.Gained))
	}
	if len(diff.Unchanged) != 1 {
		t.Errorf("new denied action should be Unchanged, got %d", len(diff.Unchanged))
	}
}

// When a forbid policy overrides a permit, the action should be Lost.
func TestDiffResultsAllowToDenyIsLost(t *testing.T) {
	base := []QueryResult{
		{Entity: types.NewEntityUID("Action", "edit"), Decision: types.Allow},
	}
	updated := []QueryResult{
		{Entity: types.NewEntityUID("Action", "edit"), Decision: types.Deny},
	}
	diff := diffResults(base, updated)
	if len(diff.Lost) != 1 {
		t.Errorf("allow→deny should be Lost, got %d", len(diff.Lost))
	}
	if len(diff.Gained) != 0 {
		t.Errorf("allow→deny should not be Gained, got %d", len(diff.Gained))
	}
}

// QueryActionDiff with no applicable actions should return empty diff.
func TestQueryActionDiffNoApplicableActions(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()

	ps := cedar.NewPolicySet()
	extraPS := mustPolicies(t, `permit (principal, action, resource);`)
	var extraPolicy *cedar.Policy
	for _, p := range extraPS.All() {
		extraPolicy = p
		break
	}

	// User+User has no actions in schema
	diff, err := s.QueryActionDiff(ps, extraPolicy, entities, ActionQueryRequest{
		Principal: types.NewEntityUID("MyApp::User", "alice"),
		Resource:  types.NewEntityUID("MyApp::User", "bob"),
		Context:   types.NewRecord(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Gained)+len(diff.Lost)+len(diff.Unchanged) != 0 {
		t.Error("expected empty diff for no applicable actions")
	}
}

// --- Authorization error propagation ---

// When a policy causes a runtime evaluation error (e.g., accessing
// a non-existent context attribute), the Query methods must surface
// the error rather than silently swallow it.
func TestQueryActionAuthorizationError(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()
	ps := mustPolicies(t, `permit (principal, action, resource) when { context.nonexistent };`)

	_, err := s.QueryAction(ps, entities, ActionQueryRequest{
		Principal: types.NewEntityUID("MyApp::User", "alice"),
		Resource:  types.NewEntityUID("MyApp::Document", "doc1"),
		Context:   types.NewRecord(nil),
	})
	if err == nil {
		t.Error("expected authorization error for missing context attribute")
	}
	if !strings.Contains(err.Error(), "authorization error") {
		t.Errorf("error should mention authorization error, got: %v", err)
	}
}

func TestQueryPrincipalAuthorizationError(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()
	ps := mustPolicies(t, `permit (principal, action, resource) when { context.nonexistent };`)

	_, err := s.QueryPrincipal(ps, entities, PrincipalQueryRequest{
		PrincipalType: "MyApp::User",
		Action:        types.NewEntityUID("MyApp::Action", "view"),
		Resource:      types.NewEntityUID("MyApp::Document", "doc1"),
		Context:       types.NewRecord(nil),
	})
	if err == nil {
		t.Error("expected authorization error for missing context attribute")
	}
}

func TestQueryResourceAuthorizationError(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()
	ps := mustPolicies(t, `permit (principal, action, resource) when { context.nonexistent };`)

	_, err := s.QueryResource(ps, entities, ResourceQueryRequest{
		Principal:    types.NewEntityUID("MyApp::User", "alice"),
		Action:       types.NewEntityUID("MyApp::Action", "view"),
		ResourceType: "MyApp::Document",
		Context:      types.NewRecord(nil),
	})
	if err == nil {
		t.Error("expected authorization error for missing context attribute")
	}
}

// --- QueryActionDiff error propagation ---

// When the baseline query encounters an error, QueryActionDiff must
// propagate it with "baseline" context.
func TestQueryActionDiffBaselineError(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()
	ps := mustPolicies(t, `permit (principal, action, resource) when { context.nonexistent };`)

	extraPS := mustPolicies(t, `permit (principal, action, resource);`)
	var extraPolicy *cedar.Policy
	for _, p := range extraPS.All() {
		extraPolicy = p
		break
	}

	_, err := s.QueryActionDiff(ps, extraPolicy, entities, ActionQueryRequest{
		Principal: types.NewEntityUID("MyApp::User", "alice"),
		Resource:  types.NewEntityUID("MyApp::Document", "doc1"),
		Context:   types.NewRecord(nil),
	})
	if err == nil {
		t.Error("expected error propagated from baseline query")
	}
	if !strings.Contains(err.Error(), "baseline") {
		t.Errorf("error should mention baseline, got: %v", err)
	}
}

// When the augmented query encounters an error (from the additional policy),
// QueryActionDiff must propagate it with "augmented" context.
func TestQueryActionDiffAugmentedError(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()

	// Base policies are clean — no errors
	basePolicies := cedar.NewPolicySet()

	// Additional policy causes evaluation error
	errorPS := mustPolicies(t, `permit (principal, action, resource) when { context.nonexistent };`)
	var errorPolicy *cedar.Policy
	for _, p := range errorPS.All() {
		errorPolicy = p
		break
	}

	_, err := s.QueryActionDiff(basePolicies, errorPolicy, entities, ActionQueryRequest{
		Principal: types.NewEntityUID("MyApp::User", "alice"),
		Resource:  types.NewEntityUID("MyApp::Document", "doc1"),
		Context:   types.NewRecord(nil),
	})
	if err == nil {
		t.Error("expected error from augmented query")
	}
	if !strings.Contains(err.Error(), "augmented") {
		t.Errorf("error should mention augmented, got: %v", err)
	}
}

// --- diffResults: new allowed action is Gained ---

func TestDiffResultsNewAllowedActionIsGained(t *testing.T) {
	base := []QueryResult{}
	updated := []QueryResult{
		{Entity: types.NewEntityUID("Action", "new_action"), Decision: types.Allow},
	}
	diff := diffResults(base, updated)
	if len(diff.Gained) != 1 {
		t.Errorf("new allowed action should be Gained, got %d", len(diff.Gained))
	}
	if len(diff.Unchanged) != 0 {
		t.Errorf("expected 0 unchanged, got %d", len(diff.Unchanged))
	}
}

// --- Introspect: not-found paths ---

func TestResourcesForActionNotFound(t *testing.T) {
	s := newTestSchema(t)
	_, ok := s.ResourcesForAction(types.EntityUID{Type: "MyApp::Action", ID: "nonexistent"})
	if ok {
		t.Error("ResourcesForAction should return false for unknown action")
	}
}
