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
	"fmt"
	"slices"

	"github.com/cedar-policy/cedar-go/types"
)

// SlotID represents a template slot identifier (e.g., "?principal", "?resource").
// Template slots are placeholders that get filled in when creating a linked policy.
type SlotID string

const (
	// SlotPrincipal is the slot for the principal in a template.
	SlotPrincipal SlotID = "?principal"
	// SlotResource is the slot for the resource in a template.
	SlotResource SlotID = "?resource"
)

// Template represents a Cedar policy template.
// A template is like a policy but can contain "slots" (placeholders) that are
// filled in when creating "linked policies" from the template.
//
// In Cedar, templates support two slots:
//   - ?principal - a placeholder in the principal scope
//   - ?resource - a placeholder in the resource scope
//
// Example template in Cedar syntax:
//
//	@id("template1")
//	permit(
//	    principal == ?principal,
//	    action == Action::"view",
//	    resource == ?resource
//	);
type Template struct {
	// ID is the unique identifier for this template.
	ID string

	// Effect is the policy effect (Permit or Forbid).
	Effect Effect

	// Annotations contains policy annotations.
	Annotations []AnnotationType

	// Position indicates where this template was defined.
	Position Position

	// Principal contains the principal scope, which may include a slot.
	Principal IsPrincipalScopeNode

	// Action contains the action scope.
	Action IsActionScopeNode

	// Resource contains the resource scope, which may include a slot.
	Resource IsResourceScopeNode

	// Conditions contains when/unless conditions.
	Conditions []ConditionType

	// Slots lists the slot IDs used in this template.
	// Valid slots are SlotPrincipal and SlotResource.
	Slots []SlotID
}

// ScopeTypeSlot represents a slot in a template scope.
// It can be used for principal or resource scopes.
type ScopeTypeSlot struct {
	ScopeNode
	PrincipalScopeNode
	ResourceScopeNode
	SlotID SlotID
}

// TemplateLink represents a link from a template to a concrete policy.
// When a template is linked, the slots are filled with concrete entity UIDs.
type TemplateLink struct {
	// TemplateID references the template being linked.
	TemplateID string

	// LinkID is the unique identifier for this linked policy.
	LinkID string

	// Values maps slot IDs to their concrete entity UID values.
	Values map[SlotID]types.EntityUID
}

// NewTemplate creates a new template with the given ID and effect.
func NewTemplate(id string, effect Effect) *Template {
	return &Template{
		ID:          id,
		Effect:      effect,
		Annotations: nil,
		Principal:   ScopeTypeAll{},
		Action:      ScopeTypeAll{},
		Resource:    ScopeTypeAll{},
		Slots:       []SlotID{},
	}
}

// PermitTemplate creates a new permit template with the given ID.
func PermitTemplate(id string) *Template {
	return NewTemplate(id, EffectPermit)
}

// ForbidTemplate creates a new forbid template with the given ID.
func ForbidTemplate(id string) *Template {
	return NewTemplate(id, EffectForbid)
}

// PrincipalSlot sets the principal scope to use a slot.
func (t *Template) PrincipalSlot() *Template {
	t.Principal = ScopeTypeSlot{SlotID: SlotPrincipal}
	if !t.HasSlot(SlotPrincipal) {
		t.Slots = append(t.Slots, SlotPrincipal)
	}
	return t
}

// PrincipalEqSlot sets the principal scope to == ?principal.
func (t *Template) PrincipalEqSlot() *Template {
	return t.PrincipalSlot()
}

// PrincipalInSlot sets the principal scope to in ?principal.
func (t *Template) PrincipalInSlot() *Template {
	t.Principal = ScopeTypeSlotIn{SlotID: SlotPrincipal}
	if !t.HasSlot(SlotPrincipal) {
		t.Slots = append(t.Slots, SlotPrincipal)
	}
	return t
}

// ResourceSlot sets the resource scope to use a slot.
func (t *Template) ResourceSlot() *Template {
	t.Resource = ScopeTypeSlot{SlotID: SlotResource}
	if !t.HasSlot(SlotResource) {
		t.Slots = append(t.Slots, SlotResource)
	}
	return t
}

// ResourceEqSlot sets the resource scope to == ?resource.
func (t *Template) ResourceEqSlot() *Template {
	return t.ResourceSlot()
}

// ResourceInSlot sets the resource scope to in ?resource.
func (t *Template) ResourceInSlot() *Template {
	t.Resource = ScopeTypeSlotIn{SlotID: SlotResource}
	if !t.HasSlot(SlotResource) {
		t.Slots = append(t.Slots, SlotResource)
	}
	return t
}

// ActionEq sets the action scope to a specific action.
func (t *Template) ActionEq(entity types.EntityUID) *Template {
	t.Action = Scope{}.Eq(entity)
	return t
}

// ActionIn sets the action scope to be in a specific action group.
func (t *Template) ActionIn(entity types.EntityUID) *Template {
	t.Action = Scope{}.In(entity)
	return t
}

// ActionInSet sets the action scope to be in a set of actions.
func (t *Template) ActionInSet(entities ...types.EntityUID) *Template {
	t.Action = Scope{}.InSet(entities)
	return t
}

// When adds a when condition to the template.
func (t *Template) When(node Node) *Template {
	t.Conditions = append(t.Conditions, ConditionType{
		Condition: ConditionWhen,
		Body:      node.v,
	})
	return t
}

// Unless adds an unless condition to the template.
func (t *Template) Unless(node Node) *Template {
	t.Conditions = append(t.Conditions, ConditionType{
		Condition: ConditionUnless,
		Body:      node.v,
	})
	return t
}

// Annotate adds an annotation to the template.
func (t *Template) Annotate(key types.Ident, value types.String) *Template {
	t.Annotations = addAnnotation(t.Annotations, key, value)
	return t
}

// HasSlot checks if a slot is already in the slots list.
func (t *Template) HasSlot(slot SlotID) bool {
	return slices.Contains(t.Slots, slot)
}

// Link creates a linked policy from this template with the given values.
// Returns an error if not all required slots are provided.
func (t *Template) Link(linkID string, values map[SlotID]types.EntityUID) (*Policy, error) {
	// Verify all slots are provided
	for _, slot := range t.Slots {
		if _, ok := values[slot]; !ok {
			return nil, fmt.Errorf("missing value for slot %s", slot)
		}
	}

	// Create the policy
	policy := newPolicy(t.Effect, t.Annotations)

	// Set position
	policy.Position = t.Position

	// Resolve principal scope
	switch s := t.Principal.(type) {
	case ScopeTypeSlot:
		policy.Principal = ScopeTypeEq{Entity: values[s.SlotID]}
	case ScopeTypeSlotIn:
		policy.Principal = ScopeTypeIn{Entity: values[s.SlotID]}
	default:
		policy.Principal = t.Principal
	}

	// Action scope is copied directly (no slots allowed in action)
	policy.Action = t.Action

	// Resolve resource scope
	switch s := t.Resource.(type) {
	case ScopeTypeSlot:
		policy.Resource = ScopeTypeEq{Entity: values[s.SlotID]}
	case ScopeTypeSlotIn:
		policy.Resource = ScopeTypeIn{Entity: values[s.SlotID]}
	default:
		policy.Resource = t.Resource
	}

	// Copy conditions
	policy.Conditions = make([]ConditionType, len(t.Conditions))
	copy(policy.Conditions, t.Conditions)

	return policy, nil
}

// ScopeTypeSlotIn represents a slot with "in" semantics in a template scope.
type ScopeTypeSlotIn struct {
	ScopeNode
	PrincipalScopeNode
	ResourceScopeNode
	SlotID SlotID
}

// TemplateSet manages a collection of templates and their linked policies.
type TemplateSet struct {
	templates map[string]*Template
	links     map[string]*TemplateLink
	policies  map[string]*Policy // Linked policies
}

// NewTemplateSet creates a new empty template set.
func NewTemplateSet() *TemplateSet {
	return &TemplateSet{
		templates: make(map[string]*Template),
		links:     make(map[string]*TemplateLink),
		policies:  make(map[string]*Policy),
	}
}

// AddTemplate adds a template to the set.
func (ts *TemplateSet) AddTemplate(t *Template) error {
	if t.ID == "" {
		return fmt.Errorf("template must have an ID")
	}
	if _, exists := ts.templates[t.ID]; exists {
		return fmt.Errorf("template %s already exists", t.ID)
	}
	ts.templates[t.ID] = t
	return nil
}

// GetTemplate retrieves a template by ID.
func (ts *TemplateSet) GetTemplate(id string) (*Template, bool) {
	t, ok := ts.templates[id]
	return t, ok
}

// Link creates a linked policy from a template.
func (ts *TemplateSet) Link(templateID, linkID string, values map[SlotID]types.EntityUID) error {
	// Get the template
	template, ok := ts.templates[templateID]
	if !ok {
		return fmt.Errorf("template %s not found", templateID)
	}

	// Check if link ID already exists
	if _, exists := ts.links[linkID]; exists {
		return fmt.Errorf("link %s already exists", linkID)
	}
	if _, exists := ts.policies[linkID]; exists {
		return fmt.Errorf("policy %s already exists", linkID)
	}

	// Create the linked policy
	policy, err := template.Link(linkID, values)
	if err != nil {
		return fmt.Errorf("failed to link template %s: %w", templateID, err)
	}

	// Store the link and policy
	ts.links[linkID] = &TemplateLink{
		TemplateID: templateID,
		LinkID:     linkID,
		Values:     values,
	}
	ts.policies[linkID] = policy

	return nil
}

// GetLinkedPolicy retrieves a linked policy by its link ID.
func (ts *TemplateSet) GetLinkedPolicy(linkID string) (*Policy, bool) {
	p, ok := ts.policies[linkID]
	return p, ok
}

// GetLink retrieves a template link by its link ID.
func (ts *TemplateSet) GetLink(linkID string) (*TemplateLink, bool) {
	l, ok := ts.links[linkID]
	return l, ok
}

// RemoveLink removes a linked policy and its link metadata.
func (ts *TemplateSet) RemoveLink(linkID string) bool {
	if _, exists := ts.links[linkID]; !exists {
		return false
	}
	delete(ts.links, linkID)
	delete(ts.policies, linkID)
	return true
}

// RemoveTemplate removes a template and all its linked policies.
func (ts *TemplateSet) RemoveTemplate(templateID string) bool {
	if _, exists := ts.templates[templateID]; !exists {
		return false
	}

	// Remove all links for this template
	for linkID, link := range ts.links {
		if link.TemplateID == templateID {
			delete(ts.links, linkID)
			delete(ts.policies, linkID)
		}
	}

	delete(ts.templates, templateID)
	return true
}

// Templates returns an iterator over all templates.
func (ts *TemplateSet) Templates() func(yield func(string, *Template) bool) {
	return func(yield func(string, *Template) bool) {
		for id, t := range ts.templates {
			if !yield(id, t) {
				return
			}
		}
	}
}

// LinkedPolicies returns an iterator over all linked policies.
func (ts *TemplateSet) LinkedPolicies() func(yield func(string, *Policy) bool) {
	return func(yield func(string, *Policy) bool) {
		for id, p := range ts.policies {
			if !yield(id, p) {
				return
			}
		}
	}
}

// Links returns an iterator over all template links.
func (ts *TemplateSet) Links() func(yield func(string, *TemplateLink) bool) {
	return func(yield func(string, *TemplateLink) bool) {
		for id, l := range ts.links {
			if !yield(id, l) {
				return
			}
		}
	}
}

// Len returns the number of templates in the set.
func (ts *TemplateSet) Len() int {
	return len(ts.templates)
}

// LinkCount returns the number of linked policies.
func (ts *TemplateSet) LinkCount() int {
	return len(ts.links)
}
