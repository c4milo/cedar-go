package schema

import (
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

func mustPolicies(t *testing.T, cedarText string) *cedar.PolicySet {
	t.Helper()
	ps, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(cedarText))
	if err != nil {
		t.Fatalf("NewPolicySetFromBytes: %v", err)
	}
	return ps
}

func testEntities() types.EntityMap {
	alice := types.NewEntityUID("MyApp::User", "alice")
	bob := types.NewEntityUID("MyApp::User", "bob")
	doc1 := types.NewEntityUID("MyApp::Document", "doc1")
	doc2 := types.NewEntityUID("MyApp::Document", "doc2")

	return types.EntityMap{
		alice: types.Entity{
			UID:        alice,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.NewRecord(types.RecordMap{"name": types.String("Alice")}),
		},
		bob: types.Entity{
			UID:        bob,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.NewRecord(types.RecordMap{"name": types.String("Bob")}),
		},
		doc1: types.Entity{
			UID:        doc1,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.NewRecord(types.RecordMap{"owner": alice}),
		},
		doc2: types.Entity{
			UID:        doc2,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.NewRecord(types.RecordMap{"owner": bob}),
		},
	}
}

func TestQueryActionPermitAll(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()
	alice := types.NewEntityUID("MyApp::User", "alice")
	doc1 := types.NewEntityUID("MyApp::Document", "doc1")

	ps := mustPolicies(t, `permit (principal, action, resource);`)

	results, err := s.QueryAction(ps, entities, ActionQueryRequest{
		Principal: alice,
		Resource:  doc1,
		Context:   types.NewRecord(nil),
	})
	if err != nil {
		t.Fatal(err)
	}

	// User + Document → view, edit, delete → all allowed
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	for _, r := range results {
		if r.Decision != types.Allow {
			t.Errorf("action %s should be Allow, got Deny", r.Entity)
		}
	}
}

func TestQueryActionPartialPermit(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()
	alice := types.NewEntityUID("MyApp::User", "alice")
	doc1 := types.NewEntityUID("MyApp::Document", "doc1")

	ps := mustPolicies(t, `permit (principal, action == MyApp::Action::"view", resource);`)

	results, err := s.QueryAction(ps, entities, ActionQueryRequest{
		Principal: alice,
		Resource:  doc1,
		Context:   types.NewRecord(nil),
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}

	allowed := 0
	denied := 0
	for _, r := range results {
		if r.Decision == types.Allow {
			allowed++
			if r.Entity.ID != "view" {
				t.Errorf("only 'view' should be allowed, got %s", r.Entity.ID)
			}
		} else {
			denied++
		}
	}
	if allowed != 1 || denied != 2 {
		t.Errorf("expected 1 allowed / 2 denied, got %d / %d", allowed, denied)
	}
}

func TestQueryActionNoPolicies(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()
	alice := types.NewEntityUID("MyApp::User", "alice")
	doc1 := types.NewEntityUID("MyApp::Document", "doc1")

	ps := cedar.NewPolicySet()

	results, err := s.QueryAction(ps, entities, ActionQueryRequest{
		Principal: alice,
		Resource:  doc1,
		Context:   types.NewRecord(nil),
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, r := range results {
		if r.Decision != types.Deny {
			t.Errorf("with no policies, %s should be Deny", r.Entity)
		}
	}
}

func TestQueryActionNoMatchingTypes(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()

	ps := mustPolicies(t, `permit (principal, action, resource);`)

	// User + User has no actions in schema
	results, err := s.QueryAction(ps, entities, ActionQueryRequest{
		Principal: types.NewEntityUID("MyApp::User", "alice"),
		Resource:  types.NewEntityUID("MyApp::User", "bob"),
		Context:   types.NewRecord(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for User+User, got %d", len(results))
	}
}

func TestQueryPrincipal(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()
	doc1 := types.NewEntityUID("MyApp::Document", "doc1")
	viewAction := types.NewEntityUID("MyApp::Action", "view")

	ps := mustPolicies(t, `permit (principal, action, resource);`)

	results, err := s.QueryPrincipal(ps, entities, PrincipalQueryRequest{
		PrincipalType: "MyApp::User",
		Action:        viewAction,
		Resource:      doc1,
		Context:       types.NewRecord(nil),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Should find alice and bob as allowed users
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for _, r := range results {
		if r.Decision != types.Allow {
			t.Errorf("principal %s should be allowed", r.Entity)
		}
	}
}

func TestQueryPrincipalInvalidAction(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()
	doc1 := types.NewEntityUID("MyApp::Document", "doc1")
	unknownAction := types.NewEntityUID("MyApp::Action", "unknown")

	ps := mustPolicies(t, `permit (principal, action, resource);`)

	_, err := s.QueryPrincipal(ps, entities, PrincipalQueryRequest{
		PrincipalType: "MyApp::User",
		Action:        unknownAction,
		Resource:      doc1,
		Context:       types.NewRecord(nil),
	})
	if err == nil {
		t.Error("expected error for unknown action")
	}
}

func TestQueryPrincipalWrongPrincipalType(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()
	doc1 := types.NewEntityUID("MyApp::Document", "doc1")
	editAction := types.NewEntityUID("MyApp::Action", "edit")

	ps := mustPolicies(t, `permit (principal, action, resource);`)

	// edit only applies to User, not Group
	_, err := s.QueryPrincipal(ps, entities, PrincipalQueryRequest{
		PrincipalType: "MyApp::Group",
		Action:        editAction,
		Resource:      doc1,
		Context:       types.NewRecord(nil),
	})
	if err == nil {
		t.Error("expected error for wrong principal type")
	}
}

func TestQueryResource(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()
	alice := types.NewEntityUID("MyApp::User", "alice")
	viewAction := types.NewEntityUID("MyApp::Action", "view")

	ps := mustPolicies(t, `permit (principal, action, resource);`)

	results, err := s.QueryResource(ps, entities, ResourceQueryRequest{
		Principal:    alice,
		Action:       viewAction,
		ResourceType: "MyApp::Document",
		Context:      types.NewRecord(nil),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Should find doc1 and doc2
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for _, r := range results {
		if r.Decision != types.Allow {
			t.Errorf("resource %s should be allowed", r.Entity)
		}
	}
}

func TestQueryResourceInvalidAction(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()
	alice := types.NewEntityUID("MyApp::User", "alice")
	unknownAction := types.NewEntityUID("MyApp::Action", "unknown")

	ps := mustPolicies(t, `permit (principal, action, resource);`)

	_, err := s.QueryResource(ps, entities, ResourceQueryRequest{
		Principal:    alice,
		Action:       unknownAction,
		ResourceType: "MyApp::Document",
		Context:      types.NewRecord(nil),
	})
	if err == nil {
		t.Error("expected error for unknown action")
	}
}

func TestQueryActionDiffGained(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()
	alice := types.NewEntityUID("MyApp::User", "alice")
	doc1 := types.NewEntityUID("MyApp::Document", "doc1")

	// Base: only view allowed
	basePolicies := mustPolicies(t, `permit (principal, action == MyApp::Action::"view", resource);`)

	// Additional: permit edit — we need to create a single Policy, not a PolicySet.
	// Parse a policy set and extract the policy.
	editPS := mustPolicies(t, `permit (principal, action == MyApp::Action::"edit", resource);`)
	var editPolicy *cedar.Policy
	for _, p := range editPS.All() {
		editPolicy = p
		break
	}

	diff, err := s.QueryActionDiff(basePolicies, editPolicy, entities, ActionQueryRequest{
		Principal: alice,
		Resource:  doc1,
		Context:   types.NewRecord(nil),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Should gain "edit"
	if len(diff.Gained) != 1 {
		t.Fatalf("expected 1 gained, got %d", len(diff.Gained))
	}
	if diff.Gained[0].Entity.ID != "edit" {
		t.Errorf("gained action = %s, want edit", diff.Gained[0].Entity.ID)
	}

	// "view" unchanged (was and still is allowed)
	hasViewUnchanged := false
	for _, r := range diff.Unchanged {
		if r.Entity.ID == "view" {
			hasViewUnchanged = true
		}
	}
	if !hasViewUnchanged {
		t.Error("'view' should be in Unchanged")
	}

	// No lost
	if len(diff.Lost) != 0 {
		t.Errorf("expected 0 lost, got %d", len(diff.Lost))
	}
}

func TestQueryActionDiffNoChange(t *testing.T) {
	s := newTestSchema(t)
	entities := testEntities()
	alice := types.NewEntityUID("MyApp::User", "alice")
	doc1 := types.NewEntityUID("MyApp::Document", "doc1")

	// Base: all allowed. Adding another permit-all changes nothing.
	basePolicies := mustPolicies(t, `permit (principal, action, resource);`)
	extraPS := mustPolicies(t, `permit (principal, action, resource);`)
	var extraPolicy *cedar.Policy
	for _, p := range extraPS.All() {
		extraPolicy = p
		break
	}

	diff, err := s.QueryActionDiff(basePolicies, extraPolicy, entities, ActionQueryRequest{
		Principal: alice,
		Resource:  doc1,
		Context:   types.NewRecord(nil),
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(diff.Gained) != 0 {
		t.Errorf("expected 0 gained, got %d", len(diff.Gained))
	}
	if len(diff.Lost) != 0 {
		t.Errorf("expected 0 lost, got %d", len(diff.Lost))
	}
	if len(diff.Unchanged) != 3 {
		t.Errorf("expected 3 unchanged, got %d", len(diff.Unchanged))
	}
}
