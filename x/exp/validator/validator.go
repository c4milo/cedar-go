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

package validator

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
)

// Validator performs type-checking validation against a schema.
type Validator struct {
	schema *schema.Schema
	// Parsed schema representation for type checking
	entityTypes map[types.EntityType]*EntityTypeInfo
	actionTypes map[types.EntityUID]*ActionTypeInfo
	commonTypes map[string]CedarType
	// maxAttributeLevel controls the maximum depth of attribute access chains.
	// A value of 0 means no limit. Level 1 allows e.g., principal.name,
	// Level 2 allows principal.manager.name, etc.
	// This implements RFC 76 level-based validation.
	maxAttributeLevel int
	// strictEntityValidation when true, validates that entities don't have
	// attributes that aren't declared in the schema.
	strictEntityValidation bool
	// allowUnknownEntityTypes when true, allows unknown entity types in
	// principalTypes and resourceTypes. This matches Lean's behavior where
	// unknown types are handled at policy validation time (impossiblePolicy).
	// By default (false), unknown types are rejected at schema validation
	// time, matching Cedar Rust behavior.
	allowUnknownEntityTypes bool
}

// ValidatorOption configures a Validator.
type ValidatorOption func(*Validator)

// WithMaxAttributeLevel sets the maximum depth of attribute access chains
// allowed in policies. This implements RFC 76 level-based validation.
//
// For example:
//   - Level 1: allows principal.name but not principal.manager.name
//   - Level 2: allows principal.manager.name but not principal.manager.department.head
//   - Level 0 (default): no limit
//
// This is useful for controlling the amount of entity data that must be
// loaded during authorization.
func WithMaxAttributeLevel(level int) ValidatorOption {
	return func(v *Validator) {
		v.maxAttributeLevel = level
	}
}

// WithAllowUnknownEntityTypes allows unknown entity types in memberOfTypes,
// principalTypes, and resourceTypes. This matches Lean's behavior where
// unknown types are accepted at schema validation time and handled during
// policy validation via the "impossiblePolicy" check.
//
// By default, unknown entity types are rejected at schema validation time,
// matching Cedar Rust behavior.
func WithAllowUnknownEntityTypes() ValidatorOption {
	return func(v *Validator) {
		v.allowUnknownEntityTypes = true
	}
}

// WithStrictEntityValidation enables strict entity validation mode.
// When enabled, entities that have attributes not declared in the schema
// will produce validation errors. By default, extra attributes are allowed.
//
// Note: If the schema defines a record type with OpenRecord=true (via
// additionalAttributes in JSON schema), extra attributes are allowed on
// that specific record type even in strict mode.
func WithStrictEntityValidation() ValidatorOption {
	return func(v *Validator) {
		v.strictEntityValidation = true
	}
}

// EntityTypeInfo contains schema information about an entity type.
type EntityTypeInfo struct {
	// Attributes defined on this entity type
	Attributes map[string]AttributeType
	// Types this entity can be a member of
	MemberOfTypes []types.EntityType
	// OpenRecord when true allows additional attributes not declared in schema
	OpenRecord bool
}

// ActionTypeInfo contains schema information about an action.
type ActionTypeInfo struct {
	// Principal types this action applies to
	PrincipalTypes []types.EntityType
	// Resource types this action applies to
	ResourceTypes []types.EntityType
	// Context type for this action
	Context RecordType
	// Actions this action is a member of
	MemberOf []types.EntityUID
}

// New creates a new Validator from a schema.
// Options can be provided to configure the validator behavior.
//
// This function validates schema well-formedness (no cycles in memberOfTypes,
// no duplicate types, referenced types exist, etc.) similar to how Cedar Rust
// validates when converting to ValidatorSchema.
func New(s *schema.Schema, opts ...ValidatorOption) (*Validator, error) {
	if s == nil {
		return nil, fmt.Errorf("schema cannot be nil")
	}

	v := &Validator{
		schema:            s,
		entityTypes:       make(map[types.EntityType]*EntityTypeInfo),
		actionTypes:       make(map[types.EntityUID]*ActionTypeInfo),
		commonTypes:       make(map[string]CedarType),
		maxAttributeLevel: 0, // 0 means no limit
	}

	// Apply options
	for _, opt := range opts {
		opt(v)
	}

	if err := v.parseSchema(); err != nil {
		return nil, fmt.Errorf("failed to parse schema: %w", err)
	}

	// Validate schema well-formedness (cycles, duplicates, unknown references)
	if err := v.validateSchemaWellFormedness(); err != nil {
		return nil, fmt.Errorf("schema validation failed: %w", err)
	}

	return v, nil
}

// parseSchema extracts type information from the schema.
func (v *Validator) parseSchema() error {
	// Get JSON representation to access schema details
	jsonBytes, err := v.schema.MarshalJSON()
	if err != nil {
		return err
	}

	// Parse the JSON schema structure
	// The schema JSON has format:
	// {
	//   "entityTypes": { "TypeName": { "shape": {...}, "memberOfTypes": [...] } },
	//   "actions": { "actionId": { "appliesTo": {...}, "context": {...} } },
	//   "commonTypes": { "TypeName": {...} }
	// }
	return v.parseSchemaJSON(jsonBytes)
}

// ValidatePolicies validates all policies in a PolicySet against the schema.
func (v *Validator) ValidatePolicies(policies *cedar.PolicySet) PolicyValidationResult {
	result := PolicyValidationResult{Valid: true}

	for id, policy := range policies.All() {
		if errs := v.validatePolicy(id, policy); len(errs) > 0 {
			result.Valid = false
			result.Errors = append(result.Errors, errs...)
		}
	}

	return result
}

// ValidateEntities validates all entities against the schema.
func (v *Validator) ValidateEntities(entities types.EntityMap) EntityValidationResult {
	result := EntityValidationResult{Valid: true}

	for uid, entity := range entities {
		if errs := v.validateEntity(uid, entity); len(errs) > 0 {
			result.Valid = false
			result.Errors = append(result.Errors, errs...)
		}
	}

	return result
}

// ValidateRequest validates a request against the schema.
func (v *Validator) ValidateRequest(req cedar.Request) RequestValidationResult {
	// Check if the action is defined
	actionUID := req.Action
	actionInfo, ok := v.actionTypes[actionUID]
	if !ok {
		return RequestValidationResult{
			Valid: false,
			Error: fmt.Sprintf("action %s is not defined in schema", actionUID),
		}
	}

	// Check if principal type is allowed for this action
	principalType := req.Principal.Type
	if !v.typeInList(principalType, actionInfo.PrincipalTypes) {
		return RequestValidationResult{
			Valid: false,
			Error: fmt.Sprintf("principal type %s is not allowed for action %s", principalType, actionUID),
		}
	}

	// Check if resource type is allowed for this action
	resourceType := req.Resource.Type
	if !v.typeInList(resourceType, actionInfo.ResourceTypes) {
		return RequestValidationResult{
			Valid: false,
			Error: fmt.Sprintf("resource type %s is not allowed for action %s", resourceType, actionUID),
		}
	}

	// Validate context matches action's context type
	if err := v.validateContext(req.Context, actionInfo.Context); err != nil {
		return RequestValidationResult{
			Valid: false,
			Error: fmt.Sprintf("context validation failed: %v", err),
		}
	}

	return RequestValidationResult{Valid: true}
}

// validatePolicy validates a single policy.
func (v *Validator) validatePolicy(id cedar.PolicyID, policy *cedar.Policy) []PolicyError {
	var errs []PolicyError

	// Get the policy AST - convert from public to internal ast type
	publicAST := policy.AST()
	policyAST := (*ast.Policy)(publicAST)

	// Check for impossible policy - a policy that can never match any valid environment.
	// This matches Lean's impossiblePolicy check.
	if v.isSchemaEmpty() {
		errs = append(errs, PolicyError{PolicyID: id, Message: "impossiblePolicy"})
		return errs
	}

	// Check scope constraints reference valid types
	scopeErrs := v.validatePolicyScope(policyAST)
	for _, msg := range scopeErrs {
		errs = append(errs, PolicyError{PolicyID: id, Message: msg})
	}

	// Check for impossible conditions (e.g., when { false } or unless { true })
	if v.hasImpossibleCondition(policyAST) {
		errs = append(errs, PolicyError{PolicyID: id, Message: "impossiblePolicy"})
	}

	// Full type-checking of conditions
	typeErrs := v.typecheckPolicy(policyAST)
	for _, msg := range typeErrs {
		errs = append(errs, PolicyError{PolicyID: id, Message: msg})
	}

	return errs
}

// isActionEntityType checks if an entity type looks like an action entity type.
// This is based on the type name pattern: "Action" or "Namespace::Action".
// This is used for scope validation where we allow action types.
func (v *Validator) isActionEntityType(t types.EntityType) bool {
	s := string(t)
	// Check for exact "Action" or ends with "::Action"
	return s == "Action" || strings.HasSuffix(s, "::Action")
}

// isKnownActionEntity checks if a specific entity UID is a defined action in the schema.
// This is stricter than isActionEntityType - it requires the exact action to be defined.
func (v *Validator) isKnownActionEntity(uid types.EntityUID) bool {
	_, exists := v.actionTypes[uid]
	return exists
}

// typeInList checks if a type is in a list of types.
func (v *Validator) typeInList(t types.EntityType, list []types.EntityType) bool {
	if len(list) == 0 {
		return true // Empty list means any type is allowed
	}
	return slices.Contains(list, t)
}
