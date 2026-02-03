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

package ast

import (
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go/types"
)

func TestTemplateCreation(t *testing.T) {
	t.Parallel()

	t.Run("PermitTemplate", func(t *testing.T) {
		t.Parallel()
		tmpl := PermitTemplate("test-template")
		if tmpl.ID != "test-template" {
			t.Errorf("Expected ID 'test-template', got %q", tmpl.ID)
		}
		if tmpl.Effect != EffectPermit {
			t.Error("Expected EffectPermit")
		}
	})

	t.Run("ForbidTemplate", func(t *testing.T) {
		t.Parallel()
		tmpl := ForbidTemplate("test-forbid")
		if tmpl.ID != "test-forbid" {
			t.Errorf("Expected ID 'test-forbid', got %q", tmpl.ID)
		}
		if tmpl.Effect != EffectForbid {
			t.Error("Expected EffectForbid")
		}
	})
}

func TestTemplateSlots(t *testing.T) {
	t.Parallel()

	t.Run("PrincipalSlot", func(t *testing.T) {
		t.Parallel()
		tmpl := PermitTemplate("t1").PrincipalSlot()
		if len(tmpl.Slots) != 1 || tmpl.Slots[0] != SlotPrincipal {
			t.Errorf("Expected [?principal] slot, got %v", tmpl.Slots)
		}
		if _, ok := tmpl.Principal.(ScopeTypeSlot); !ok {
			t.Error("Expected ScopeTypeSlot for principal")
		}
	})

	t.Run("ResourceSlot", func(t *testing.T) {
		t.Parallel()
		tmpl := PermitTemplate("t1").ResourceSlot()
		if len(tmpl.Slots) != 1 || tmpl.Slots[0] != SlotResource {
			t.Errorf("Expected [?resource] slot, got %v", tmpl.Slots)
		}
		if _, ok := tmpl.Resource.(ScopeTypeSlot); !ok {
			t.Error("Expected ScopeTypeSlot for resource")
		}
	})

	t.Run("BothSlots", func(t *testing.T) {
		t.Parallel()
		tmpl := PermitTemplate("t1").PrincipalSlot().ResourceSlot()
		if len(tmpl.Slots) != 2 {
			t.Errorf("Expected 2 slots, got %d", len(tmpl.Slots))
		}
	})

	t.Run("PrincipalInSlot", func(t *testing.T) {
		t.Parallel()
		tmpl := PermitTemplate("t1").PrincipalInSlot()
		if _, ok := tmpl.Principal.(ScopeTypeSlotIn); !ok {
			t.Error("Expected ScopeTypeSlotIn for principal")
		}
	})

	t.Run("ResourceInSlot", func(t *testing.T) {
		t.Parallel()
		tmpl := PermitTemplate("t1").ResourceInSlot()
		if _, ok := tmpl.Resource.(ScopeTypeSlotIn); !ok {
			t.Error("Expected ScopeTypeSlotIn for resource")
		}
	})

	t.Run("DuplicateSlotNotAdded", func(t *testing.T) {
		t.Parallel()
		tmpl := PermitTemplate("t1").PrincipalSlot().PrincipalSlot()
		if len(tmpl.Slots) != 1 {
			t.Errorf("Expected 1 slot (no duplicates), got %d", len(tmpl.Slots))
		}
	})
}

func TestTemplateActions(t *testing.T) {
	t.Parallel()

	action := types.NewEntityUID("Action", "view")

	t.Run("ActionEq", func(t *testing.T) {
		t.Parallel()
		tmpl := PermitTemplate("t1").ActionEq(action)
		if s, ok := tmpl.Action.(ScopeTypeEq); !ok || s.Entity != action {
			t.Error("Expected ActionEq scope")
		}
	})

	t.Run("ActionIn", func(t *testing.T) {
		t.Parallel()
		tmpl := PermitTemplate("t1").ActionIn(action)
		if s, ok := tmpl.Action.(ScopeTypeIn); !ok || s.Entity != action {
			t.Error("Expected ActionIn scope")
		}
	})

	t.Run("ActionInSet", func(t *testing.T) {
		t.Parallel()
		action2 := types.NewEntityUID("Action", "edit")
		tmpl := PermitTemplate("t1").ActionInSet(action, action2)
		if s, ok := tmpl.Action.(ScopeTypeInSet); !ok || len(s.Entities) != 2 {
			t.Error("Expected ActionInSet scope with 2 actions")
		}
	})
}

func TestTemplateConditions(t *testing.T) {
	t.Parallel()

	t.Run("When", func(t *testing.T) {
		t.Parallel()
		tmpl := PermitTemplate("t1").When(True())
		if len(tmpl.Conditions) != 1 || tmpl.Conditions[0].Condition != ConditionWhen {
			t.Error("Expected 1 when condition")
		}
	})

	t.Run("Unless", func(t *testing.T) {
		t.Parallel()
		tmpl := PermitTemplate("t1").Unless(False())
		if len(tmpl.Conditions) != 1 || tmpl.Conditions[0].Condition != ConditionUnless {
			t.Error("Expected 1 unless condition")
		}
	})
}

func TestTemplateAnnotations(t *testing.T) {
	t.Parallel()

	tmpl := PermitTemplate("t1").Annotate("reason", "test annotation")
	found := false
	for _, ann := range tmpl.Annotations {
		if string(ann.Key) == "reason" && string(ann.Value) == "test annotation" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected annotation to be added")
	}
}

func TestTemplateLinking(t *testing.T) {
	t.Parallel()

	t.Run("LinkWithPrincipalSlot", func(t *testing.T) {
		t.Parallel()
		tmpl := PermitTemplate("t1").
			PrincipalSlot().
			ActionEq(types.NewEntityUID("Action", "view"))

		alice := types.NewEntityUID("User", "alice")
		policy, err := tmpl.Link("link1", map[SlotID]types.EntityUID{
			SlotPrincipal: alice,
		})

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if policy == nil {
			t.Fatal("Expected policy, got nil")
		}
		if s, ok := policy.Principal.(ScopeTypeEq); !ok || s.Entity != alice {
			t.Error("Expected principal == alice")
		}
	})

	t.Run("LinkWithResourceSlot", func(t *testing.T) {
		t.Parallel()
		tmpl := PermitTemplate("t1").
			ResourceSlot().
			ActionEq(types.NewEntityUID("Action", "view"))

		doc := types.NewEntityUID("Document", "report.pdf")
		policy, err := tmpl.Link("link1", map[SlotID]types.EntityUID{
			SlotResource: doc,
		})

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if s, ok := policy.Resource.(ScopeTypeEq); !ok || s.Entity != doc {
			t.Error("Expected resource == document")
		}
	})

	t.Run("LinkWithBothSlots", func(t *testing.T) {
		t.Parallel()
		tmpl := PermitTemplate("t1").
			PrincipalSlot().
			ResourceSlot().
			ActionEq(types.NewEntityUID("Action", "view"))

		alice := types.NewEntityUID("User", "alice")
		doc := types.NewEntityUID("Document", "report.pdf")

		policy, err := tmpl.Link("link1", map[SlotID]types.EntityUID{
			SlotPrincipal: alice,
			SlotResource:  doc,
		})

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if s, ok := policy.Principal.(ScopeTypeEq); !ok || s.Entity != alice {
			t.Error("Expected principal == alice")
		}
		if s, ok := policy.Resource.(ScopeTypeEq); !ok || s.Entity != doc {
			t.Error("Expected resource == document")
		}
	})

	t.Run("LinkWithInSlots", func(t *testing.T) {
		t.Parallel()
		tmpl := PermitTemplate("t1").
			PrincipalInSlot().
			ResourceInSlot()

		group := types.NewEntityUID("Group", "admins")
		folder := types.NewEntityUID("Folder", "shared")

		policy, err := tmpl.Link("link1", map[SlotID]types.EntityUID{
			SlotPrincipal: group,
			SlotResource:  folder,
		})

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if s, ok := policy.Principal.(ScopeTypeIn); !ok || s.Entity != group {
			t.Error("Expected principal in group")
		}
		if s, ok := policy.Resource.(ScopeTypeIn); !ok || s.Entity != folder {
			t.Error("Expected resource in folder")
		}
	})

	t.Run("LinkMissingSlot", func(t *testing.T) {
		t.Parallel()
		tmpl := PermitTemplate("t1").PrincipalSlot().ResourceSlot()

		_, err := tmpl.Link("link1", map[SlotID]types.EntityUID{
			SlotPrincipal: types.NewEntityUID("User", "alice"),
			// Missing SlotResource
		})

		if err == nil {
			t.Error("Expected error for missing slot")
		}
		if !strings.Contains(err.Error(), "?resource") {
			t.Errorf("Expected error to mention ?resource, got: %v", err)
		}
	})

	t.Run("LinkWithConditions", func(t *testing.T) {
		t.Parallel()
		tmpl := PermitTemplate("t1").
			PrincipalSlot().
			When(Context().Access("approved").Equal(True()))

		policy, err := tmpl.Link("link1", map[SlotID]types.EntityUID{
			SlotPrincipal: types.NewEntityUID("User", "alice"),
		})

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if len(policy.Conditions) != 1 {
			t.Errorf("Expected 1 condition, got %d", len(policy.Conditions))
		}
	})
}

func TestTemplateSet(t *testing.T) {
	t.Parallel()

	t.Run("AddAndGetTemplate", func(t *testing.T) {
		t.Parallel()
		ts := NewTemplateSet()
		tmpl := PermitTemplate("template1").PrincipalSlot()

		if err := ts.AddTemplate(tmpl); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		got, ok := ts.GetTemplate("template1")
		if !ok {
			t.Fatal("Expected to find template")
		}
		if got.ID != "template1" {
			t.Errorf("Expected ID 'template1', got %q", got.ID)
		}
	})

	t.Run("AddDuplicateTemplate", func(t *testing.T) {
		t.Parallel()
		ts := NewTemplateSet()
		tmpl1 := PermitTemplate("template1")
		tmpl2 := PermitTemplate("template1")

		_ = ts.AddTemplate(tmpl1)
		err := ts.AddTemplate(tmpl2)

		if err == nil {
			t.Error("Expected error for duplicate template")
		}
	})

	t.Run("AddTemplateWithoutID", func(t *testing.T) {
		t.Parallel()
		ts := NewTemplateSet()
		tmpl := &Template{Effect: EffectPermit}

		err := ts.AddTemplate(tmpl)
		if err == nil {
			t.Error("Expected error for template without ID")
		}
	})

	t.Run("LinkTemplate", func(t *testing.T) {
		t.Parallel()
		ts := NewTemplateSet()
		tmpl := PermitTemplate("template1").PrincipalSlot()
		_ = ts.AddTemplate(tmpl)

		err := ts.Link("template1", "link1", map[SlotID]types.EntityUID{
			SlotPrincipal: types.NewEntityUID("User", "alice"),
		})

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		policy, ok := ts.GetLinkedPolicy("link1")
		if !ok {
			t.Fatal("Expected to find linked policy")
		}
		if policy == nil {
			t.Fatal("Expected non-nil policy")
		}
	})

	t.Run("LinkNonExistentTemplate", func(t *testing.T) {
		t.Parallel()
		ts := NewTemplateSet()

		err := ts.Link("nonexistent", "link1", map[SlotID]types.EntityUID{})
		if err == nil {
			t.Error("Expected error for non-existent template")
		}
	})

	t.Run("LinkDuplicateID", func(t *testing.T) {
		t.Parallel()
		ts := NewTemplateSet()
		tmpl := PermitTemplate("template1").PrincipalSlot()
		_ = ts.AddTemplate(tmpl)

		_ = ts.Link("template1", "link1", map[SlotID]types.EntityUID{
			SlotPrincipal: types.NewEntityUID("User", "alice"),
		})

		err := ts.Link("template1", "link1", map[SlotID]types.EntityUID{
			SlotPrincipal: types.NewEntityUID("User", "bob"),
		})

		if err == nil {
			t.Error("Expected error for duplicate link ID")
		}
	})

	t.Run("GetLink", func(t *testing.T) {
		t.Parallel()
		ts := NewTemplateSet()
		tmpl := PermitTemplate("template1").PrincipalSlot()
		_ = ts.AddTemplate(tmpl)
		_ = ts.Link("template1", "link1", map[SlotID]types.EntityUID{
			SlotPrincipal: types.NewEntityUID("User", "alice"),
		})

		link, ok := ts.GetLink("link1")
		if !ok {
			t.Fatal("Expected to find link")
		}
		if link.TemplateID != "template1" {
			t.Errorf("Expected template ID 'template1', got %q", link.TemplateID)
		}
		if link.Values[SlotPrincipal] != types.NewEntityUID("User", "alice") {
			t.Error("Expected principal to be alice")
		}
	})

	t.Run("RemoveLink", func(t *testing.T) {
		t.Parallel()
		ts := NewTemplateSet()
		tmpl := PermitTemplate("template1").PrincipalSlot()
		_ = ts.AddTemplate(tmpl)
		_ = ts.Link("template1", "link1", map[SlotID]types.EntityUID{
			SlotPrincipal: types.NewEntityUID("User", "alice"),
		})

		if !ts.RemoveLink("link1") {
			t.Error("Expected RemoveLink to return true")
		}
		if _, ok := ts.GetLinkedPolicy("link1"); ok {
			t.Error("Expected linked policy to be removed")
		}
		if _, ok := ts.GetLink("link1"); ok {
			t.Error("Expected link to be removed")
		}
	})

	t.Run("RemoveNonExistentLink", func(t *testing.T) {
		t.Parallel()
		ts := NewTemplateSet()
		if ts.RemoveLink("nonexistent") {
			t.Error("Expected RemoveLink to return false for non-existent link")
		}
	})

	t.Run("RemoveTemplate", func(t *testing.T) {
		t.Parallel()
		ts := NewTemplateSet()
		tmpl := PermitTemplate("template1").PrincipalSlot()
		_ = ts.AddTemplate(tmpl)
		_ = ts.Link("template1", "link1", map[SlotID]types.EntityUID{
			SlotPrincipal: types.NewEntityUID("User", "alice"),
		})
		_ = ts.Link("template1", "link2", map[SlotID]types.EntityUID{
			SlotPrincipal: types.NewEntityUID("User", "bob"),
		})

		if !ts.RemoveTemplate("template1") {
			t.Error("Expected RemoveTemplate to return true")
		}
		if _, ok := ts.GetTemplate("template1"); ok {
			t.Error("Expected template to be removed")
		}
		if _, ok := ts.GetLinkedPolicy("link1"); ok {
			t.Error("Expected link1 to be removed")
		}
		if _, ok := ts.GetLinkedPolicy("link2"); ok {
			t.Error("Expected link2 to be removed")
		}
	})

	t.Run("RemoveNonExistentTemplate", func(t *testing.T) {
		t.Parallel()
		ts := NewTemplateSet()
		if ts.RemoveTemplate("nonexistent") {
			t.Error("Expected RemoveTemplate to return false for non-existent template")
		}
	})

	t.Run("Iterators", func(t *testing.T) {
		t.Parallel()
		ts := NewTemplateSet()
		tmpl1 := PermitTemplate("template1").PrincipalSlot()
		tmpl2 := PermitTemplate("template2").ResourceSlot()
		_ = ts.AddTemplate(tmpl1)
		_ = ts.AddTemplate(tmpl2)
		_ = ts.Link("template1", "link1", map[SlotID]types.EntityUID{
			SlotPrincipal: types.NewEntityUID("User", "alice"),
		})

		// Test Templates iterator
		templateCount := 0
		for range ts.Templates() {
			templateCount++
		}
		if templateCount != 2 {
			t.Errorf("Expected 2 templates, got %d", templateCount)
		}

		// Test LinkedPolicies iterator
		policyCount := 0
		for range ts.LinkedPolicies() {
			policyCount++
		}
		if policyCount != 1 {
			t.Errorf("Expected 1 linked policy, got %d", policyCount)
		}

		// Test Links iterator
		linkCount := 0
		for range ts.Links() {
			linkCount++
		}
		if linkCount != 1 {
			t.Errorf("Expected 1 link, got %d", linkCount)
		}
	})

	t.Run("Len", func(t *testing.T) {
		t.Parallel()
		ts := NewTemplateSet()
		if ts.Len() != 0 {
			t.Errorf("Expected 0, got %d", ts.Len())
		}
		_ = ts.AddTemplate(PermitTemplate("t1"))
		if ts.Len() != 1 {
			t.Errorf("Expected 1, got %d", ts.Len())
		}
	})

	t.Run("LinkCount", func(t *testing.T) {
		t.Parallel()
		ts := NewTemplateSet()
		tmpl := PermitTemplate("t1").PrincipalSlot()
		_ = ts.AddTemplate(tmpl)

		if ts.LinkCount() != 0 {
			t.Errorf("Expected 0, got %d", ts.LinkCount())
		}

		_ = ts.Link("t1", "link1", map[SlotID]types.EntityUID{
			SlotPrincipal: types.NewEntityUID("User", "alice"),
		})
		if ts.LinkCount() != 1 {
			t.Errorf("Expected 1, got %d", ts.LinkCount())
		}
	})
}

func TestSlotIDConstants(t *testing.T) {
	t.Parallel()

	if SlotPrincipal != "?principal" {
		t.Errorf("Expected SlotPrincipal to be '?principal', got %q", SlotPrincipal)
	}
	if SlotResource != "?resource" {
		t.Errorf("Expected SlotResource to be '?resource', got %q", SlotResource)
	}
}

func TestTemplateEqSlotAliases(t *testing.T) {
	t.Parallel()

	t.Run("PrincipalEqSlot", func(t *testing.T) {
		t.Parallel()
		tmpl := PermitTemplate("t1").PrincipalEqSlot()
		if len(tmpl.Slots) != 1 || tmpl.Slots[0] != SlotPrincipal {
			t.Errorf("Expected [?principal] slot, got %v", tmpl.Slots)
		}
		if _, ok := tmpl.Principal.(ScopeTypeSlot); !ok {
			t.Error("Expected ScopeTypeSlot for principal")
		}
	})

	t.Run("ResourceEqSlot", func(t *testing.T) {
		t.Parallel()
		tmpl := PermitTemplate("t1").ResourceEqSlot()
		if len(tmpl.Slots) != 1 || tmpl.Slots[0] != SlotResource {
			t.Errorf("Expected [?resource] slot, got %v", tmpl.Slots)
		}
		if _, ok := tmpl.Resource.(ScopeTypeSlot); !ok {
			t.Error("Expected ScopeTypeSlot for resource")
		}
	})
}

func TestTemplateSetIteratorEarlyTermination(t *testing.T) {
	t.Parallel()

	ts := NewTemplateSet()
	tmpl1 := PermitTemplate("template1").PrincipalSlot()
	tmpl2 := PermitTemplate("template2").PrincipalSlot()
	tmpl3 := PermitTemplate("template3").PrincipalSlot()
	_ = ts.AddTemplate(tmpl1)
	_ = ts.AddTemplate(tmpl2)
	_ = ts.AddTemplate(tmpl3)
	_ = ts.Link("template1", "link1", map[SlotID]types.EntityUID{
		SlotPrincipal: types.NewEntityUID("User", "alice"),
	})
	_ = ts.Link("template2", "link2", map[SlotID]types.EntityUID{
		SlotPrincipal: types.NewEntityUID("User", "bob"),
	})
	_ = ts.Link("template3", "link3", map[SlotID]types.EntityUID{
		SlotPrincipal: types.NewEntityUID("User", "charlie"),
	})

	// Test Templates iterator early termination
	t.Run("TemplatesEarlyTermination", func(t *testing.T) {
		count := 0
		for _, tmpl := range ts.Templates() {
			count++
			if tmpl.ID != "" {
				break // Early termination
			}
		}
		if count != 1 {
			t.Errorf("Expected 1 iteration before break, got %d", count)
		}
	})

	// Test LinkedPolicies iterator early termination
	t.Run("LinkedPoliciesEarlyTermination", func(t *testing.T) {
		count := 0
		for range ts.LinkedPolicies() {
			count++
			break // Early termination
		}
		if count != 1 {
			t.Errorf("Expected 1 iteration before break, got %d", count)
		}
	})

	// Test Links iterator early termination
	t.Run("LinksEarlyTermination", func(t *testing.T) {
		count := 0
		for range ts.Links() {
			count++
			break // Early termination
		}
		if count != 1 {
			t.Errorf("Expected 1 iteration before break, got %d", count)
		}
	})
}

func TestTemplateSetLinkFailure(t *testing.T) {
	t.Parallel()

	ts := NewTemplateSet()
	tmpl := PermitTemplate("template1").PrincipalSlot().ResourceSlot()
	_ = ts.AddTemplate(tmpl)

	// Link fails because of missing slot
	err := ts.Link("template1", "link1", map[SlotID]types.EntityUID{
		SlotPrincipal: types.NewEntityUID("User", "alice"),
		// Missing SlotResource
	})

	if err == nil {
		t.Error("Expected error for missing slot")
	}
	if !strings.Contains(err.Error(), "failed to link template") {
		t.Errorf("Expected 'failed to link template' in error, got: %v", err)
	}
}

func TestTemplateLinkWithNoSlots(t *testing.T) {
	t.Parallel()

	// Template with no slots - should link successfully with empty values
	tmpl := PermitTemplate("t1").ActionEq(types.NewEntityUID("Action", "view"))

	policy, err := tmpl.Link("link1", map[SlotID]types.EntityUID{})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if policy == nil {
		t.Fatal("Expected policy, got nil")
	}
	// Principal and Resource should remain as "all" (ScopeTypeAll)
	if _, ok := policy.Principal.(ScopeTypeAll); !ok {
		t.Error("Expected principal to be ScopeTypeAll")
	}
	if _, ok := policy.Resource.(ScopeTypeAll); !ok {
		t.Error("Expected resource to be ScopeTypeAll")
	}
}

func TestTemplateSetLinkPolicyAlreadyExists(t *testing.T) {
	t.Parallel()

	// Test the defensive check where policy ID exists but link ID doesn't
	// This tests the check at TemplateSet.Link line 323-324
	ts := NewTemplateSet()
	tmpl := PermitTemplate("template1").PrincipalSlot()
	_ = ts.AddTemplate(tmpl)

	// Directly manipulate the internal policies map to simulate an inconsistent state
	// (this shouldn't happen in normal usage, but the code has a defensive check for it)
	ts.policies["conflicting_id"] = Permit()

	err := ts.Link("template1", "conflicting_id", map[SlotID]types.EntityUID{
		SlotPrincipal: types.NewEntityUID("User", "alice"),
	})

	if err == nil {
		t.Error("Expected error for policy already exists")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("Expected 'already exists' in error, got: %v", err)
	}
}
