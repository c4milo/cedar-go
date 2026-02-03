package cedar

import (
	"fmt"
	"testing"

	"github.com/cedar-policy/cedar-go/internal/testutil"
	"github.com/cedar-policy/cedar-go/types"
)

func TestPolicySetIndexing(t *testing.T) {
	t.Parallel()

	t.Run("BuildIndex", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		var p Policy
		testutil.OK(t, p.UnmarshalCedar([]byte(`permit(
			principal == User::"alice",
			action == Action::"read",
			resource == Document::"doc1"
		);`)))
		ps.Add("policy1", &p)

		// Index should be dirty initially
		testutil.Equals(t, ps.indexDirty, true)

		// Build index
		ps.BuildIndex()

		// Index should be clean now
		testutil.Equals(t, ps.indexDirty, false)
		testutil.Equals(t, ps.index != nil, true)
	})

	t.Run("IndexInvalidatedOnAdd", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		var p1 Policy
		testutil.OK(t, p1.UnmarshalCedar([]byte(`permit(principal, action, resource);`)))
		ps.Add("policy1", &p1)
		ps.BuildIndex()

		testutil.Equals(t, ps.indexDirty, false)

		// Adding a policy should invalidate the index
		var p2 Policy
		testutil.OK(t, p2.UnmarshalCedar([]byte(`permit(principal, action, resource);`)))
		ps.Add("policy2", &p2)

		testutil.Equals(t, ps.indexDirty, true)
	})

	t.Run("IndexInvalidatedOnRemove", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		var p1 Policy
		testutil.OK(t, p1.UnmarshalCedar([]byte(`permit(principal, action, resource);`)))
		ps.Add("policy1", &p1)
		ps.BuildIndex()

		testutil.Equals(t, ps.indexDirty, false)

		// Removing a policy should invalidate the index
		ps.Remove("policy1")

		testutil.Equals(t, ps.indexDirty, true)
	})

	t.Run("forRequest_ActionIndex", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		// Add policies with different actions
		for i := range 100 {
			var p Policy
			testutil.OK(t, p.UnmarshalCedar([]byte(fmt.Sprintf(`permit(
				principal,
				action == Action::"action%d",
				resource
			);`, i))))
			ps.Add(PolicyID(fmt.Sprintf("policy%d", i)), &p)
		}

		ps.BuildIndex()

		// Request for action42 should only match policy42
		req := Request{
			Principal: types.NewEntityUID("User", "alice"),
			Action:    types.NewEntityUID("Action", "action42"),
			Resource:  types.NewEntityUID("Document", "doc1"),
		}

		count := 0
		for range ps.forRequest(req) {
			count++
		}
		testutil.Equals(t, count, 1)
	})

	t.Run("forRequest_PrincipalTypeIndex", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		// Add policies with different principal types
		principalTypes := []string{"User", "Admin", "Service", "Bot"}
		for i, typ := range principalTypes {
			var p Policy
			testutil.OK(t, p.UnmarshalCedar([]byte(fmt.Sprintf(`permit(
				principal is %s,
				action,
				resource
			);`, typ))))
			ps.Add(PolicyID(fmt.Sprintf("policy%d", i)), &p)
		}

		// Add more policies to exceed threshold
		for i := range 50 {
			var p Policy
			testutil.OK(t, p.UnmarshalCedar([]byte(fmt.Sprintf(`permit(
				principal == Other::"other%d",
				action,
				resource
			);`, i))))
			ps.Add(PolicyID(fmt.Sprintf("other%d", i)), &p)
		}

		ps.BuildIndex()

		// Request with User principal should match User policy
		req := Request{
			Principal: types.NewEntityUID("User", "alice"),
			Action:    types.NewEntityUID("Action", "read"),
			Resource:  types.NewEntityUID("Document", "doc1"),
		}

		count := 0
		for range ps.forRequest(req) {
			count++
		}
		testutil.Equals(t, count, 1)
	})

	t.Run("forRequest_ResourceTypeIndex", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		// Add policies with different resource types
		for i := range 100 {
			var p Policy
			testutil.OK(t, p.UnmarshalCedar([]byte(fmt.Sprintf(`permit(
				principal,
				action,
				resource is Type%d
			);`, i))))
			ps.Add(PolicyID(fmt.Sprintf("policy%d", i)), &p)
		}

		ps.BuildIndex()

		// Request for Type42 should only match policy42
		req := Request{
			Principal: types.NewEntityUID("User", "alice"),
			Action:    types.NewEntityUID("Action", "read"),
			Resource:  types.NewEntityUID("Type42", "res1"),
		}

		count := 0
		for range ps.forRequest(req) {
			count++
		}
		testutil.Equals(t, count, 1)
	})

	t.Run("forRequest_Wildcards", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		// Add wildcard policy
		var pWild Policy
		testutil.OK(t, pWild.UnmarshalCedar([]byte(`permit(principal, action, resource);`)))
		ps.Add("wildcard", &pWild)

		// Add specific policies
		for i := range 60 {
			var p Policy
			testutil.OK(t, p.UnmarshalCedar([]byte(fmt.Sprintf(`permit(
				principal == User::"user%d",
				action == Action::"action%d",
				resource == Doc::"doc%d"
			);`, i, i, i))))
			ps.Add(PolicyID(fmt.Sprintf("policy%d", i)), &p)
		}

		ps.BuildIndex()

		// Any request should match the wildcard policy
		req := Request{
			Principal: types.NewEntityUID("Unknown", "x"),
			Action:    types.NewEntityUID("Unknown", "y"),
			Resource:  types.NewEntityUID("Unknown", "z"),
		}

		count := 0
		for range ps.forRequest(req) {
			count++
		}
		testutil.Equals(t, count, 1) // Only wildcard matches
	})

	t.Run("forRequest_ActionInSet", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		// Add policy with action in set
		var p Policy
		testutil.OK(t, p.UnmarshalCedar([]byte(`permit(
			principal,
			action in [Action::"read", Action::"write", Action::"delete"],
			resource
		);`)))
		ps.Add("multi-action", &p)

		// Add filler policies
		for i := range 60 {
			var pf Policy
			testutil.OK(t, pf.UnmarshalCedar([]byte(fmt.Sprintf(`permit(
				principal,
				action == Action::"other%d",
				resource
			);`, i))))
			ps.Add(PolicyID(fmt.Sprintf("filler%d", i)), &pf)
		}

		ps.BuildIndex()

		// Request for "read" action should match
		req := Request{
			Principal: types.NewEntityUID("User", "alice"),
			Action:    types.NewEntityUID("Action", "read"),
			Resource:  types.NewEntityUID("Doc", "doc1"),
		}

		count := 0
		for range ps.forRequest(req) {
			count++
		}
		testutil.Equals(t, count, 1)

		// Request for "write" action should also match
		req.Action = types.NewEntityUID("Action", "write")
		count = 0
		for range ps.forRequest(req) {
			count++
		}
		testutil.Equals(t, count, 1)
	})

	t.Run("forRequest_PrincipalIn", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		// "principal in X" is treated as wildcard for indexing
		var p Policy
		testutil.OK(t, p.UnmarshalCedar([]byte(`permit(
			principal in Group::"admins",
			action,
			resource
		);`)))
		ps.Add("in-group", &p)

		// Add filler policies
		for i := range 60 {
			var pf Policy
			testutil.OK(t, pf.UnmarshalCedar([]byte(fmt.Sprintf(`permit(
				principal == Other::"other%d",
				action,
				resource
			);`, i))))
			ps.Add(PolicyID(fmt.Sprintf("filler%d", i)), &pf)
		}

		ps.BuildIndex()

		// Any principal type should match (treated as wildcard)
		req := Request{
			Principal: types.NewEntityUID("User", "alice"),
			Action:    types.NewEntityUID("Action", "read"),
			Resource:  types.NewEntityUID("Doc", "doc1"),
		}

		found := false
		for id := range ps.forRequest(req) {
			if id == "in-group" {
				found = true
			}
		}
		testutil.Equals(t, found, true)
	})

	t.Run("forRequest_IsIn", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		// "principal is User in Group::admins" should index by type
		var p Policy
		testutil.OK(t, p.UnmarshalCedar([]byte(`permit(
			principal is User in Group::"admins",
			action,
			resource
		);`)))
		ps.Add("is-in", &p)

		// Add filler policies with different types
		for i := range 60 {
			var pf Policy
			testutil.OK(t, pf.UnmarshalCedar([]byte(fmt.Sprintf(`permit(
				principal is Other%d,
				action,
				resource
			);`, i))))
			ps.Add(PolicyID(fmt.Sprintf("filler%d", i)), &pf)
		}

		ps.BuildIndex()

		// User principal should match
		req := Request{
			Principal: types.NewEntityUID("User", "alice"),
			Action:    types.NewEntityUID("Action", "read"),
			Resource:  types.NewEntityUID("Doc", "doc1"),
		}

		found := false
		for id := range ps.forRequest(req) {
			if id == "is-in" {
				found = true
			}
		}
		testutil.Equals(t, found, true)

		// Non-User principal should not match
		req.Principal = types.NewEntityUID("Service", "api")
		found = false
		for id := range ps.forRequest(req) {
			if id == "is-in" {
				found = true
			}
		}
		testutil.Equals(t, found, false)
	})

	t.Run("forRequest_ResourceEq", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		// Add policies with resource == specific entity (different types)
		for i := range 60 {
			var p Policy
			testutil.OK(t, p.UnmarshalCedar([]byte(fmt.Sprintf(`permit(
				principal,
				action,
				resource == Type%d::"doc%d"
			);`, i, i))))
			ps.Add(PolicyID(fmt.Sprintf("policy%d", i)), &p)
		}

		ps.BuildIndex()

		// Request for Type42 should only match policy42 (index by resource type)
		req := Request{
			Principal: types.NewEntityUID("User", "alice"),
			Action:    types.NewEntityUID("Action", "read"),
			Resource:  types.NewEntityUID("Type42", "doc42"),
		}

		count := 0
		for range ps.forRequest(req) {
			count++
		}
		testutil.Equals(t, count, 1)
	})

	t.Run("forRequest_ResourceIn", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		// "resource in X" is treated as wildcard for indexing
		var p Policy
		testutil.OK(t, p.UnmarshalCedar([]byte(`permit(
			principal,
			action,
			resource in Folder::"shared"
		);`)))
		ps.Add("in-folder", &p)

		// Add filler policies
		for i := range 60 {
			var pf Policy
			testutil.OK(t, pf.UnmarshalCedar([]byte(fmt.Sprintf(`permit(
				principal,
				action,
				resource == Other::"other%d"
			);`, i))))
			ps.Add(PolicyID(fmt.Sprintf("filler%d", i)), &pf)
		}

		ps.BuildIndex()

		// Any resource type should match (treated as wildcard)
		req := Request{
			Principal: types.NewEntityUID("User", "alice"),
			Action:    types.NewEntityUID("Action", "read"),
			Resource:  types.NewEntityUID("Document", "doc1"),
		}

		found := false
		for id := range ps.forRequest(req) {
			if id == "in-folder" {
				found = true
			}
		}
		testutil.Equals(t, found, true)
	})

	t.Run("forRequest_ResourceIsIn", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		// "resource is Document in Folder::shared" indexes by type
		var p Policy
		testutil.OK(t, p.UnmarshalCedar([]byte(`permit(
			principal,
			action,
			resource is Document in Folder::"shared"
		);`)))
		ps.Add("is-in", &p)

		// Add filler policies with different types
		for i := range 60 {
			var pf Policy
			testutil.OK(t, pf.UnmarshalCedar([]byte(fmt.Sprintf(`permit(
				principal,
				action,
				resource is Other%d
			);`, i))))
			ps.Add(PolicyID(fmt.Sprintf("filler%d", i)), &pf)
		}

		ps.BuildIndex()

		// Document resource should match
		req := Request{
			Principal: types.NewEntityUID("User", "alice"),
			Action:    types.NewEntityUID("Action", "read"),
			Resource:  types.NewEntityUID("Document", "doc1"),
		}

		found := false
		for id := range ps.forRequest(req) {
			if id == "is-in" {
				found = true
			}
		}
		testutil.Equals(t, found, true)

		// Non-Document resource should not match
		req.Resource = types.NewEntityUID("Image", "img1")
		found = false
		for id := range ps.forRequest(req) {
			if id == "is-in" {
				found = true
			}
		}
		testutil.Equals(t, found, false)
	})

	t.Run("forRequest_ActionIn", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		// "action in X" is treated as wildcard
		var p Policy
		testutil.OK(t, p.UnmarshalCedar([]byte(`permit(
			principal,
			action in Action::"write-ops",
			resource
		);`)))
		ps.Add("action-in", &p)

		// Add filler policies
		for i := range 60 {
			var pf Policy
			testutil.OK(t, pf.UnmarshalCedar([]byte(fmt.Sprintf(`permit(
				principal,
				action == Action::"other%d",
				resource
			);`, i))))
			ps.Add(PolicyID(fmt.Sprintf("filler%d", i)), &pf)
		}

		ps.BuildIndex()

		// Any action should match (treated as wildcard)
		req := Request{
			Principal: types.NewEntityUID("User", "alice"),
			Action:    types.NewEntityUID("Action", "create"),
			Resource:  types.NewEntityUID("Document", "doc1"),
		}

		found := false
		for id := range ps.forRequest(req) {
			if id == "action-in" {
				found = true
			}
		}
		testutil.Equals(t, found, true)
	})
}

func TestForRequestEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("NoMatchingAction", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		// Add wildcard policy to ensure some policies exist
		var pWild Policy
		testutil.OK(t, pWild.UnmarshalCedar([]byte(`permit(principal, action, resource);`)))
		ps.Add("wildcard", &pWild)

		// Add specific action policies
		for i := range 60 {
			var p Policy
			testutil.OK(t, p.UnmarshalCedar([]byte(fmt.Sprintf(`permit(
				principal,
				action == Action::"action%d",
				resource
			);`, i))))
			ps.Add(PolicyID(fmt.Sprintf("policy%d", i)), &p)
		}

		ps.BuildIndex()

		// Request for non-existent action should still return wildcard
		req := Request{
			Principal: types.NewEntityUID("User", "alice"),
			Action:    types.NewEntityUID("Action", "nonexistent"),
			Resource:  types.NewEntityUID("Document", "doc1"),
		}

		count := 0
		for range ps.forRequest(req) {
			count++
		}
		testutil.Equals(t, count, 1) // Only wildcard matches
	})

	t.Run("EarlyBreak", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		// Add many wildcard policies
		for i := range 100 {
			var p Policy
			testutil.OK(t, p.UnmarshalCedar([]byte(`permit(principal, action, resource);`)))
			ps.Add(PolicyID(fmt.Sprintf("policy%d", i)), &p)
		}

		ps.BuildIndex()

		req := Request{
			Principal: types.NewEntityUID("User", "alice"),
			Action:    types.NewEntityUID("Action", "read"),
			Resource:  types.NewEntityUID("Document", "doc1"),
		}

		// Break after first policy
		count := 0
		for range ps.forRequest(req) {
			count++
			break
		}
		testutil.Equals(t, count, 1)
	})

	t.Run("NoMatchingPrincipalType", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		// Add wildcard policy
		var pWild Policy
		testutil.OK(t, pWild.UnmarshalCedar([]byte(`permit(principal, action, resource);`)))
		ps.Add("wildcard", &pWild)

		// Add type-specific policies
		for i := range 60 {
			var p Policy
			testutil.OK(t, p.UnmarshalCedar([]byte(fmt.Sprintf(`permit(
				principal is Admin%d,
				action,
				resource
			);`, i))))
			ps.Add(PolicyID(fmt.Sprintf("policy%d", i)), &p)
		}

		ps.BuildIndex()

		// Request for non-existent principal type should still return wildcard
		req := Request{
			Principal: types.NewEntityUID("User", "alice"),
			Action:    types.NewEntityUID("Action", "read"),
			Resource:  types.NewEntityUID("Document", "doc1"),
		}

		count := 0
		for range ps.forRequest(req) {
			count++
		}
		testutil.Equals(t, count, 1)
	})

	t.Run("NoMatchingResourceType", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		// Add wildcard policy
		var pWild Policy
		testutil.OK(t, pWild.UnmarshalCedar([]byte(`permit(principal, action, resource);`)))
		ps.Add("wildcard", &pWild)

		// Add type-specific policies
		for i := range 60 {
			var p Policy
			testutil.OK(t, p.UnmarshalCedar([]byte(fmt.Sprintf(`permit(
				principal,
				action,
				resource is Type%d
			);`, i))))
			ps.Add(PolicyID(fmt.Sprintf("policy%d", i)), &p)
		}

		ps.BuildIndex()

		// Request for non-existent resource type should still return wildcard
		req := Request{
			Principal: types.NewEntityUID("User", "alice"),
			Action:    types.NewEntityUID("Action", "read"),
			Resource:  types.NewEntityUID("Unknown", "x"),
		}

		count := 0
		for range ps.forRequest(req) {
			count++
		}
		testutil.Equals(t, count, 1)
	})

	t.Run("PolicyFilteredByMultipleIndexes", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		// Add policies that match action but NOT principal type
		// This triggers the "return false" path when checking across indexes
		for i := range 30 {
			var p Policy
			testutil.OK(t, p.UnmarshalCedar([]byte(fmt.Sprintf(`permit(
				principal is Admin,
				action == Action::"read",
				resource
			);`))))
			ps.Add(PolicyID(fmt.Sprintf("admin%d", i)), &p)
		}

		// Add policies that match principal type but NOT action
		for i := range 30 {
			var p Policy
			testutil.OK(t, p.UnmarshalCedar([]byte(fmt.Sprintf(`permit(
				principal is User,
				action == Action::"write",
				resource
			);`))))
			ps.Add(PolicyID(fmt.Sprintf("user%d", i)), &p)
		}

		// Add one policy that matches BOTH
		var pMatch Policy
		testutil.OK(t, pMatch.UnmarshalCedar([]byte(`permit(
			principal is User,
			action == Action::"read",
			resource
		);`)))
		ps.Add("matching", &pMatch)

		ps.BuildIndex()

		// Request should only match the one policy that matches both indexes
		req := Request{
			Principal: types.NewEntityUID("User", "alice"),
			Action:    types.NewEntityUID("Action", "read"),
			Resource:  types.NewEntityUID("Document", "doc1"),
		}

		count := 0
		matchID := ""
		for id := range ps.forRequest(req) {
			count++
			matchID = string(id)
		}
		testutil.Equals(t, count, 1)
		testutil.Equals(t, matchID, "matching")
	})

	t.Run("EarlyBreakFromIndexed", func(t *testing.T) {
		t.Parallel()
		ps := NewPolicySet()

		// Add many policies with same action (will be in indexed, not wildcards)
		for i := range 100 {
			var p Policy
			testutil.OK(t, p.UnmarshalCedar([]byte(fmt.Sprintf(`permit(
				principal,
				action == Action::"read",
				resource
			);`))))
			ps.Add(PolicyID(fmt.Sprintf("policy%d", i)), &p)
		}

		ps.BuildIndex()

		req := Request{
			Principal: types.NewEntityUID("User", "alice"),
			Action:    types.NewEntityUID("Action", "read"),
			Resource:  types.NewEntityUID("Document", "doc1"),
		}

		// Break after first policy (tests early return from indexed iteration)
		count := 0
		for range ps.forRequest(req) {
			count++
			break
		}
		testutil.Equals(t, count, 1)
	})
}

func TestAuthorizeUsesIndex(t *testing.T) {
	t.Parallel()

	// Create a policy set with >50 policies to trigger indexing
	ps := NewPolicySet()

	// Add one policy that will match
	var pMatch Policy
	testutil.OK(t, pMatch.UnmarshalCedar([]byte(`permit(
		principal == User::"alice",
		action == Action::"read",
		resource == Document::"doc1"
	);`)))
	ps.Add("matching", &pMatch)

	// Add 60 policies that won't match
	for i := range 60 {
		var p Policy
		testutil.OK(t, p.UnmarshalCedar([]byte(fmt.Sprintf(`permit(
			principal == User::"user%d",
			action == Action::"action%d",
			resource == Doc::"doc%d"
		);`, i, i, i))))
		ps.Add(PolicyID(fmt.Sprintf("policy%d", i)), &p)
	}

	entities := types.EntityMap{}
	req := Request{
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "read"),
		Resource:  types.NewEntityUID("Document", "doc1"),
	}

	// Authorize should use indexing and find the matching policy
	decision, diag := Authorize(ps, entities, req)
	testutil.Equals(t, decision, Allow)
	testutil.Equals(t, len(diag.Reasons), 1)
	testutil.Equals(t, diag.Reasons[0].PolicyID, PolicyID("matching"))
}
