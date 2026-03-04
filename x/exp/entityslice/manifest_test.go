package entityslice

import (
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
)

// manifestAsserter helps verify EntityManifest fields.
type manifestAsserter struct {
	t        *testing.T
	manifest *EntityManifest
}

func assertManifest(t *testing.T, manifest *EntityManifest) *manifestAsserter {
	return &manifestAsserter{t: t, manifest: manifest}
}

func (a *manifestAsserter) maxLevel(want int) *manifestAsserter {
	a.t.Helper()
	if a.manifest.MaxLevel != want {
		a.t.Errorf("Expected MaxLevel %d, got %d", want, a.manifest.MaxLevel)
	}
	return a
}

func (a *manifestAsserter) hasLiteral(uid types.EntityUID) *manifestAsserter {
	a.t.Helper()
	if !a.manifest.EntityLiterals[uid] {
		a.t.Errorf("Expected %v to be in EntityLiterals", uid)
	}
	return a
}

func TestComputeManifestBasic(t *testing.T) {
	policyStr := `permit(principal, action, resource);`

	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	manifest, err := ComputeManifest(nil, policies)
	if err != nil {
		t.Fatalf("ComputeManifest failed: %v", err)
	}

	// No attribute access, so MaxLevel should be 0
	if manifest.MaxLevel != 0 {
		t.Errorf("Expected MaxLevel 0, got %d", manifest.MaxLevel)
	}

	// No entity literals
	if len(manifest.EntityLiterals) != 0 {
		t.Errorf("Expected 0 entity literals, got %d", len(manifest.EntityLiterals))
	}
}

func TestComputeManifestWithEntityLiterals(t *testing.T) {
	policyStr := `permit(principal == User::"alice", action, resource);`

	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	manifest, err := ComputeManifest(nil, policies)
	if err != nil {
		t.Fatalf("ComputeManifest failed: %v", err)
	}

	alice := types.NewEntityUID("User", "alice")
	if !manifest.EntityLiterals[alice] {
		t.Error("Expected alice to be in EntityLiterals")
	}
}

func TestComputeManifestWithAttributeAccess(t *testing.T) {
	policyStr := `permit(principal, action, resource) when { principal.name == "alice" };`

	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	manifest, err := ComputeManifest(nil, policies)
	if err != nil {
		t.Fatalf("ComputeManifest failed: %v", err)
	}

	// One level of attribute access
	if manifest.MaxLevel != 1 {
		t.Errorf("Expected MaxLevel 1, got %d", manifest.MaxLevel)
	}
}

func TestComputeManifestWithChainedAttributeAccess(t *testing.T) {
	policyStr := `permit(principal, action, resource) when { principal.manager.department == "engineering" };`

	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	manifest, err := ComputeManifest(nil, policies)
	if err != nil {
		t.Fatalf("ComputeManifest failed: %v", err)
	}

	// Two levels of attribute access
	if manifest.MaxLevel != 2 {
		t.Errorf("Expected MaxLevel 2, got %d", manifest.MaxLevel)
	}
}

func TestSliceEntitiesBasic(t *testing.T) {
	policyStr := `permit(principal, action, resource) when { principal in Group::"admins" };`

	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	manifest, err := ComputeManifest(nil, policies)
	if err != nil {
		t.Fatalf("ComputeManifest failed: %v", err)
	}

	// Create entities
	alice := types.NewEntityUID("User", "alice")
	admins := types.NewEntityUID("Group", "admins")
	bob := types.NewEntityUID("User", "bob")
	users := types.NewEntityUID("Group", "users")
	action := types.NewEntityUID("Action", "view")
	doc := types.NewEntityUID("Doc", "readme")

	entities := types.EntityMap{
		alice: {
			UID:        alice,
			Parents:    types.NewEntityUIDSet(admins),
			Attributes: types.Record{},
		},
		admins: {
			UID:        admins,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.Record{},
		},
		bob: {
			UID:        bob,
			Parents:    types.NewEntityUIDSet(users),
			Attributes: types.Record{},
		},
		users: {
			UID:        users,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.Record{},
		},
	}

	req := cedar.Request{
		Principal: alice,
		Action:    action,
		Resource:  doc,
		Context:   types.Record{},
	}

	slice := manifest.SliceEntities(entities, req)

	// Should contain alice (principal) and admins (ancestor)
	if _, ok := slice[alice]; !ok {
		t.Error("Slice should contain alice (principal)")
	}
	if _, ok := slice[admins]; !ok {
		t.Error("Slice should contain admins (alice's parent)")
	}

	// Should NOT contain bob or users (not related to request)
	if _, ok := slice[bob]; ok {
		t.Error("Slice should not contain bob")
	}
	if _, ok := slice[users]; ok {
		t.Error("Slice should not contain users")
	}
}

func TestSliceEntitiesWithAttributeRefs(t *testing.T) {
	policyStr := `permit(principal, action, resource) when { principal.manager == User::"boss" };`

	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	manifest, err := ComputeManifest(nil, policies)
	if err != nil {
		t.Fatalf("ComputeManifest failed: %v", err)
	}

	alice := types.NewEntityUID("User", "alice")
	boss := types.NewEntityUID("User", "boss")
	action := types.NewEntityUID("Action", "view")
	doc := types.NewEntityUID("Doc", "readme")

	entities := types.EntityMap{
		alice: {
			UID:     alice,
			Parents: types.NewEntityUIDSet(),
			Attributes: types.NewRecord(types.RecordMap{
				"manager": boss,
			}),
		},
		boss: {
			UID:        boss,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.Record{},
		},
	}

	req := cedar.Request{
		Principal: alice,
		Action:    action,
		Resource:  doc,
		Context:   types.Record{},
	}

	slice := manifest.SliceEntities(entities, req)

	// Should contain alice
	if _, ok := slice[alice]; !ok {
		t.Error("Slice should contain alice")
	}

	// Should contain boss (referenced in alice's attribute, and entity literal)
	if _, ok := slice[boss]; !ok {
		t.Error("Slice should contain boss (referenced in alice's manager attribute)")
	}
}

func TestSliceEntitiesPreservesDecision(t *testing.T) {
	policyStr := `permit(principal, action, resource) when { principal in Group::"admins" };`

	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	manifest, err := ComputeManifest(nil, policies)
	if err != nil {
		t.Fatalf("ComputeManifest failed: %v", err)
	}

	alice := types.NewEntityUID("User", "alice")
	admins := types.NewEntityUID("Group", "admins")
	bob := types.NewEntityUID("User", "bob")
	users := types.NewEntityUID("Group", "users")
	action := types.NewEntityUID("Action", "view")
	doc := types.NewEntityUID("Doc", "readme")

	entities := types.EntityMap{
		alice: {
			UID:        alice,
			Parents:    types.NewEntityUIDSet(admins),
			Attributes: types.Record{},
		},
		admins: {
			UID:        admins,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.Record{},
		},
		bob: {
			UID:        bob,
			Parents:    types.NewEntityUIDSet(users),
			Attributes: types.Record{},
		},
		users: {
			UID:        users,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.Record{},
		},
	}

	// Test Alice (should be allowed)
	aliceReq := cedar.Request{
		Principal: alice,
		Action:    action,
		Resource:  doc,
		Context:   types.Record{},
	}

	fullDecision, _ := cedar.Authorize(policies, entities, aliceReq)
	slice := manifest.SliceEntities(entities, aliceReq)
	sliceDecision, _ := cedar.Authorize(policies, slice, aliceReq)

	if fullDecision != sliceDecision {
		t.Errorf("Alice: decisions differ - full=%v, slice=%v", fullDecision, sliceDecision)
	}
	if fullDecision != types.Allow {
		t.Errorf("Alice should be allowed, got %v", fullDecision)
	}

	// Test Bob (should be denied)
	bobReq := cedar.Request{
		Principal: bob,
		Action:    action,
		Resource:  doc,
		Context:   types.Record{},
	}

	fullDecision, _ = cedar.Authorize(policies, entities, bobReq)
	slice = manifest.SliceEntities(entities, bobReq)
	sliceDecision, _ = cedar.Authorize(policies, slice, bobReq)

	if fullDecision != sliceDecision {
		t.Errorf("Bob: decisions differ - full=%v, slice=%v", fullDecision, sliceDecision)
	}
	if fullDecision != types.Deny {
		t.Errorf("Bob should be denied, got %v", fullDecision)
	}
}

func TestSlicingEntityGetter(t *testing.T) {
	alice := types.NewEntityUID("User", "alice")
	bob := types.NewEntityUID("User", "bob")

	entities := types.EntityMap{
		alice: {
			UID:        alice,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.Record{},
		},
		bob: {
			UID:        bob,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.Record{},
		},
	}

	// Create a slice that only includes alice
	slice := types.EntityMap{
		alice: entities[alice],
	}

	getter := NewSlicingEntityGetter(entities, slice)

	// Should be able to get alice
	entity, ok := getter.Get(alice)
	if !ok {
		t.Error("Should be able to get alice")
	}
	if entity.UID != alice {
		t.Errorf("Expected alice, got %v", entity.UID)
	}

	// Should NOT be able to get bob (not in slice)
	_, ok = getter.Get(bob)
	if ok {
		t.Error("Should not be able to get bob (not in slice)")
	}
}

func TestComputeManifestWithScopeConstraints(t *testing.T) {
	tests := []struct {
		name           string
		policy         string
		expectedLits   []types.EntityUID
		expectedMaxLvl int
	}{
		{
			name:           "eq constraint",
			policy:         `permit(principal == User::"alice", action, resource);`,
			expectedLits:   []types.EntityUID{types.NewEntityUID("User", "alice")},
			expectedMaxLvl: 0,
		},
		{
			name:           "in constraint",
			policy:         `permit(principal in Group::"admins", action, resource);`,
			expectedLits:   []types.EntityUID{types.NewEntityUID("Group", "admins")},
			expectedMaxLvl: 0,
		},
		{
			name:   "action in set",
			policy: `permit(principal, action in [Action::"read", Action::"write"], resource);`,
			expectedLits: []types.EntityUID{
				types.NewEntityUID("Action", "read"),
				types.NewEntityUID("Action", "write"),
			},
			expectedMaxLvl: 0,
		},
		{
			name:           "resource is in",
			policy:         `permit(principal, action, resource is Doc in Folder::"docs");`,
			expectedLits:   []types.EntityUID{types.NewEntityUID("Folder", "docs")},
			expectedMaxLvl: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest := parseAndComputeManifest(t, tc.policy)
			a := assertManifest(t, manifest).maxLevel(tc.expectedMaxLvl)
			for _, uid := range tc.expectedLits {
				a.hasLiteral(uid)
			}
		})
	}
}

// parseAndComputeManifest is a helper that parses a policy and computes its manifest.
func parseAndComputeManifest(t *testing.T, policyStr string) *EntityManifest {
	t.Helper()
	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	manifest, err := ComputeManifest(nil, policies)
	if err != nil {
		t.Fatalf("ComputeManifest failed: %v", err)
	}
	return manifest
}

func TestSliceEntitiesWithContextRefs(t *testing.T) {
	policyStr := `permit(principal, action, resource) when { context.approver == User::"manager" };`

	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	manifest, err := ComputeManifest(nil, policies)
	if err != nil {
		t.Fatalf("ComputeManifest failed: %v", err)
	}

	alice := types.NewEntityUID("User", "alice")
	manager := types.NewEntityUID("User", "manager")
	action := types.NewEntityUID("Action", "view")
	doc := types.NewEntityUID("Doc", "readme")

	entities := types.EntityMap{
		alice: {
			UID:        alice,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.Record{},
		},
		manager: {
			UID:        manager,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.Record{},
		},
	}

	// Context references the manager entity
	req := cedar.Request{
		Principal: alice,
		Action:    action,
		Resource:  doc,
		Context: types.NewRecord(types.RecordMap{
			"approver": manager,
		}),
	}

	slice := manifest.SliceEntities(entities, req)

	// Should contain alice (principal)
	if _, ok := slice[alice]; !ok {
		t.Error("Slice should contain alice")
	}

	// Should contain manager (from context and entity literal)
	if _, ok := slice[manager]; !ok {
		t.Error("Slice should contain manager (referenced in context)")
	}
}

func TestComputeManifestFromSchema(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {
			"User": {},
			"Document": {}
		},
		"actions": {
			"view": {
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["Document"]
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policyStr := `permit(principal, action, resource);`
	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	manifest, err := ComputeManifestFromSchema(s, policies)
	if err != nil {
		t.Fatalf("ComputeManifestFromSchema failed: %v", err)
	}

	if manifest.MaxLevel != 0 {
		t.Errorf("Expected MaxLevel 0, got %d", manifest.MaxLevel)
	}
}

func TestAnalyzeNodeWithTags(t *testing.T) {
	// Test getTag operation
	policyStr := `permit(principal, action, resource) when { principal.getTag("role") == "admin" };`
	manifest := parseAndComputeManifest(t, policyStr)
	if manifest.MaxLevel < 1 {
		t.Errorf("Expected MaxLevel >= 1 for getTag, got %d", manifest.MaxLevel)
	}
}

func TestAnalyzeNodeWithAllBinaryOperators(t *testing.T) {
	tests := []struct {
		name   string
		policy string
	}{
		{"and", `permit(principal, action, resource) when { true && false };`},
		{"or", `permit(principal, action, resource) when { true || false };`},
		{"equals", `permit(principal, action, resource) when { 1 == 1 };`},
		{"notEquals", `permit(principal, action, resource) when { 1 != 2 };`},
		{"lessThan", `permit(principal, action, resource) when { 1 < 2 };`},
		{"lessThanOrEqual", `permit(principal, action, resource) when { 1 <= 2 };`},
		{"greaterThan", `permit(principal, action, resource) when { 2 > 1 };`},
		{"greaterThanOrEqual", `permit(principal, action, resource) when { 2 >= 1 };`},
		{"add", `permit(principal, action, resource) when { (1 + 1) == 2 };`},
		{"sub", `permit(principal, action, resource) when { (2 - 1) == 1 };`},
		{"mult", `permit(principal, action, resource) when { (2 * 2) == 4 };`},
		{"contains", `permit(principal, action, resource) when { [1, 2, 3].contains(1) };`},
		{"containsAll", `permit(principal, action, resource) when { [1, 2, 3].containsAll([1, 2]) };`},
		{"containsAny", `permit(principal, action, resource) when { [1, 2, 3].containsAny([3, 4]) };`},
		{"in", `permit(principal, action, resource) when { principal in Group::"admins" };`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_ = parseAndComputeManifest(t, tc.policy)
		})
	}
}

func TestAnalyzeNodeWithUnaryOperators(t *testing.T) {
	tests := []struct {
		name   string
		policy string
	}{
		{"not", `permit(principal, action, resource) when { !false };`},
		{"negate", `permit(principal, action, resource) when { -1 < 0 };`},
		{"has", `permit(principal, action, resource) when { principal has name };`},
		{"like", `permit(principal, action, resource) when { "test" like "*est" };`},
		{"is", `permit(principal, action, resource) when { principal is User };`},
		{"isEmpty", `permit(principal, action, resource) when { [].isEmpty() };`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_ = parseAndComputeManifest(t, tc.policy)
		})
	}
}

func TestAnalyzeNodeWithContainers(t *testing.T) {
	tests := []struct {
		name   string
		policy string
	}{
		{"set", `permit(principal, action, resource) when { [1, 2, 3].contains(1) };`},
		{"record", `permit(principal, action, resource) when { {"a": 1}.a == 1 };`},
		{"ifThenElse", `permit(principal, action, resource) when { if true then 1 else 2 == 1 };`},
		{"extensionCall", `permit(principal, action, resource) when { ip("192.168.1.1").isIpv4() };`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_ = parseAndComputeManifest(t, tc.policy)
		})
	}
}

func TestAnalyzeNodeIsIn(t *testing.T) {
	policyStr := `permit(principal is User in Group::"admins", action, resource);`
	manifest := parseAndComputeManifest(t, policyStr)
	if !manifest.EntityLiterals[types.NewEntityUID("Group", "admins")] {
		t.Error("Expected Group::admins in EntityLiterals for is-in scope")
	}
}

func TestAnalyzeNodeHasTag(t *testing.T) {
	policyStr := `permit(principal, action, resource) when { principal.hasTag("role") };`
	_ = parseAndComputeManifest(t, policyStr)
}

func TestSliceEntitiesWithSetInContext(t *testing.T) {
	policyStr := `permit(principal, action, resource) when { context.approvers.contains(User::"manager") };`

	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	manifest, err := ComputeManifest(nil, policies)
	if err != nil {
		t.Fatalf("ComputeManifest failed: %v", err)
	}

	alice := types.NewEntityUID("User", "alice")
	manager := types.NewEntityUID("User", "manager")
	reviewer := types.NewEntityUID("User", "reviewer")
	action := types.NewEntityUID("Action", "view")
	doc := types.NewEntityUID("Doc", "readme")

	entities := types.EntityMap{
		alice:    {UID: alice, Parents: types.NewEntityUIDSet(), Attributes: types.Record{}},
		manager:  {UID: manager, Parents: types.NewEntityUIDSet(), Attributes: types.Record{}},
		reviewer: {UID: reviewer, Parents: types.NewEntityUIDSet(), Attributes: types.Record{}},
	}

	// Context with a set containing entity refs
	req := cedar.Request{
		Principal: alice,
		Action:    action,
		Resource:  doc,
		Context: types.NewRecord(types.RecordMap{
			"approvers": types.NewSet(manager, reviewer),
		}),
	}

	slice := manifest.SliceEntities(entities, req)

	if _, ok := slice[alice]; !ok {
		t.Error("Slice should contain alice")
	}
	if _, ok := slice[manager]; !ok {
		t.Error("Slice should contain manager (from context set)")
	}
	if _, ok := slice[reviewer]; !ok {
		t.Error("Slice should contain reviewer (from context set)")
	}
}

func TestSliceEntitiesWithRecordInContext(t *testing.T) {
	policyStr := `permit(principal, action, resource) when { context.meta.owner == User::"owner" };`

	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	manifest, err := ComputeManifest(nil, policies)
	if err != nil {
		t.Fatalf("ComputeManifest failed: %v", err)
	}

	alice := types.NewEntityUID("User", "alice")
	owner := types.NewEntityUID("User", "owner")
	action := types.NewEntityUID("Action", "view")
	doc := types.NewEntityUID("Doc", "readme")

	entities := types.EntityMap{
		alice: {UID: alice, Parents: types.NewEntityUIDSet(), Attributes: types.Record{}},
		owner: {UID: owner, Parents: types.NewEntityUIDSet(), Attributes: types.Record{}},
	}

	// Context with nested record containing entity ref
	req := cedar.Request{
		Principal: alice,
		Action:    action,
		Resource:  doc,
		Context: types.NewRecord(types.RecordMap{
			"meta": types.NewRecord(types.RecordMap{
				"owner": owner,
			}),
		}),
	}

	slice := manifest.SliceEntities(entities, req)

	if _, ok := slice[owner]; !ok {
		t.Error("Slice should contain owner (from nested context record)")
	}
}

func TestComputeManifestFromSchemaWithNilSchema(t *testing.T) {
	policies := cedar.NewPolicySet()
	_, err := ComputeManifestFromSchema(nil, policies)
	if err == nil {
		t.Error("Expected error for nil schema")
	}
}

func TestComputeManifestFromSchemaValid(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["User"]
					}
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	manifest, err := ComputeManifestFromSchema(s, policies)
	if err != nil {
		t.Fatalf("ComputeManifestFromSchema failed: %v", err)
	}
	if manifest == nil {
		t.Error("Expected non-nil manifest")
	}
}

func TestComputeManifestWithNegateOperator(t *testing.T) {
	policyStr := `permit(principal, action, resource) when { -principal.score > 0 };`

	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	manifest, err := ComputeManifest(nil, policies)
	if err != nil {
		t.Fatalf("ComputeManifest failed: %v", err)
	}

	// Negate operator with attribute access
	if manifest.MaxLevel < 1 {
		t.Errorf("Expected MaxLevel >= 1 for negate operator with attribute, got %d", manifest.MaxLevel)
	}
}

func TestComputeManifestWithIsInOperator(t *testing.T) {
	policyStr := `permit(principal, action, resource) when { principal is User in Group::"admins" };`

	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	manifest, err := ComputeManifest(nil, policies)
	if err != nil {
		t.Fatalf("ComputeManifest failed: %v", err)
	}

	admins := types.NewEntityUID("Group", "admins")
	if !manifest.EntityLiterals[admins] {
		t.Error("Expected Group::admins to be in EntityLiterals")
	}
}

// TestAnalyzeNodeWithNil tests the nil check in analyzeNode
func TestAnalyzeNodeWithNil(t *testing.T) {
	manifest := &EntityManifest{
		EntityLiterals: make(map[types.EntityUID]bool),
	}
	// This should not panic - it's a no-op
	analyzeNode(manifest, nil, 0)
	if manifest.MaxLevel != 0 {
		t.Error("Expected MaxLevel to remain 0 for nil node")
	}
}

// TestGetBinaryChildrenFallback tests the fallback case in getBinaryChildren
func TestGetBinaryChildrenFallback(t *testing.T) {
	// NodeValue is not a binary operator, so it should return nil
	node := ast.NodeValue{Value: types.Long(42)}
	children := getBinaryChildren(node)
	if children != nil {
		t.Error("Expected nil for non-binary node")
	}
}
