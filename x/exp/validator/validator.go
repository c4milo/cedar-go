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

// PolicyValidationResult contains the result of validating policies.
type PolicyValidationResult struct {
	Valid  bool
	Errors []PolicyError
}

// PolicyError represents a validation error for a specific policy.
type PolicyError struct {
	PolicyID cedar.PolicyID
	Message  string
}

// EntityValidationResult contains the result of validating entities.
type EntityValidationResult struct {
	Valid  bool
	Errors []EntityError
}

// EntityError represents a validation error for a specific entity.
type EntityError struct {
	EntityUID types.EntityUID
	Message   string
}

// RequestValidationResult contains the result of validating a request.
type RequestValidationResult struct {
	Valid bool
	Error string
}

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

	// Check scope constraints reference valid types
	scopeErrs := v.validatePolicyScope(policyAST)
	for _, msg := range scopeErrs {
		errs = append(errs, PolicyError{PolicyID: id, Message: msg})
	}

	// Full type-checking of conditions
	typeErrs := v.typecheckPolicy(policyAST)
	for _, msg := range typeErrs {
		errs = append(errs, PolicyError{PolicyID: id, Message: msg})
	}

	return errs
}

// validateEntity validates a single entity.
func (v *Validator) validateEntity(uid types.EntityUID, entity types.Entity) []EntityError {
	var errs []EntityError

	// Check if entity type is defined
	entityInfo, ok := v.entityTypes[uid.Type]
	if !ok {
		// Check if it's an action entity (Action or Namespace::Action)
		if v.isActionEntityType(uid.Type) {
			return errs // Action entities are handled differently
		}
		errs = append(errs, EntityError{
			EntityUID: uid,
			Message:   fmt.Sprintf("entity type %s is not defined in schema", uid.Type),
		})
		return errs
	}

	// Validate attributes
	for attrName, attrType := range entityInfo.Attributes {
		attrVal, exists := entity.Attributes.Get(types.String(attrName))
		if !exists {
			if attrType.Required {
				errs = append(errs, EntityError{
					EntityUID: uid,
					Message:   fmt.Sprintf("required attribute %s is missing", attrName),
				})
			}
			continue
		}

		if err := v.validateValue(attrVal, attrType.Type); err != nil {
			errs = append(errs, EntityError{
				EntityUID: uid,
				Message:   fmt.Sprintf("attribute %s: %v", attrName, err),
			})
		}
	}

	// Check for undeclared attributes in strict mode
	if v.strictEntityValidation && !entityInfo.OpenRecord {
		for attrName := range entity.Attributes.All() {
			if _, declared := entityInfo.Attributes[string(attrName)]; !declared {
				errs = append(errs, EntityError{
					EntityUID: uid,
					Message:   fmt.Sprintf("attribute %s is not declared in schema", attrName),
				})
			}
		}
	}

	// Validate parent relationships
	for parent := range entity.Parents.All() {
		if !v.typeInList(parent.Type, entityInfo.MemberOfTypes) {
			errs = append(errs, EntityError{
				EntityUID: uid,
				Message:   fmt.Sprintf("entity cannot be member of type %s", parent.Type),
			})
		}
	}

	return errs
}

// validateContext validates context against an expected record type.
func (v *Validator) validateContext(context types.Value, expected RecordType) error {
	rec, ok := context.(types.Record)
	if !ok {
		return fmt.Errorf("context must be a record, got %T", context)
	}

	for attrName, attrType := range expected.Attributes {
		val, exists := rec.Get(types.String(attrName))
		if !exists {
			if attrType.Required {
				return fmt.Errorf("required context attribute %s is missing", attrName)
			}
			continue
		}

		if err := v.validateValue(val, attrType.Type); err != nil {
			return fmt.Errorf("context attribute %s: %v", attrName, err)
		}
	}

	// Check for undeclared attributes in strict mode
	if v.strictEntityValidation && !expected.OpenRecord {
		for attrName := range rec.All() {
			if _, declared := expected.Attributes[string(attrName)]; !declared {
				return fmt.Errorf("context attribute %s is not declared in schema", attrName)
			}
		}
	}

	return nil
}

// validateValue validates a value against an expected type.
func (v *Validator) validateValue(val types.Value, expected CedarType) error {
	actual := v.inferType(val)
	if !TypesMatch(expected, actual) {
		return fmt.Errorf("expected %s, got %s", expected, actual)
	}
	return nil
}

// inferType infers the Cedar type from a value.
func (v *Validator) inferType(val types.Value) CedarType {
	switch typedVal := val.(type) {
	case types.Boolean:
		return BoolType{}
	case types.Long:
		return LongType{}
	case types.String:
		return StringType{}
	case types.EntityUID:
		return EntityType{Name: typedVal.Type}
	case types.Set:
		return v.inferSetType(typedVal)
	case types.Record:
		return v.inferRecordType(typedVal)
	case types.Decimal:
		return ExtensionType{Name: "decimal"}
	case types.IPAddr:
		return ExtensionType{Name: "ipaddr"}
	case types.Datetime:
		return ExtensionType{Name: "datetime"}
	case types.Duration:
		return ExtensionType{Name: "duration"}
	default:
		return UnknownType{}
	}
}

// inferSetType infers the type of a Set value.
func (v *Validator) inferSetType(s types.Set) CedarType {
	if s.Len() == 0 {
		return SetType{Element: UnknownType{}}
	}
	// Infer element type from first element
	for elem := range s.All() {
		return SetType{Element: v.inferType(elem)}
	}
	return SetType{Element: UnknownType{}}
}

// inferRecordType infers the type of a Record value.
func (v *Validator) inferRecordType(r types.Record) CedarType {
	attrs := make(map[string]AttributeType)
	for k, rv := range r.All() {
		attrs[string(k)] = AttributeType{Type: v.inferType(rv), Required: true}
	}
	return RecordType{Attributes: attrs}
}

// isActionEntityType checks if an entity type is an action type.
// This handles both "Action" and namespaced "Namespace::Action" types.
func (v *Validator) isActionEntityType(t types.EntityType) bool {
	s := string(t)
	// Check for exact "Action" or ends with "::Action"
	return s == "Action" || strings.HasSuffix(s, "::Action")
}

// typeInList checks if a type is in a list of types.
func (v *Validator) typeInList(t types.EntityType, list []types.EntityType) bool {
	if len(list) == 0 {
		return true // Empty list means any type is allowed
	}
	return slices.Contains(list, t)
}

// validatePolicyScope validates the scope of a policy.
func (v *Validator) validatePolicyScope(policyAST *ast.Policy) []string {
	var errs []string

	v.validateEntityScope(policyAST.Principal, "principal", &errs)
	v.validateActionScope(policyAST.Action, &errs)
	v.validateEntityScope(policyAST.Resource, "resource", &errs)
	v.validateActionAppliesTo(policyAST, &errs)

	return errs
}

// validateEntityScope validates principal or resource scope.
func (v *Validator) validateEntityScope(scope ast.IsScopeNode, scopeName string, errs *[]string) {
	switch s := scope.(type) {
	case ast.ScopeTypeEq:
		v.checkEntityType(s.Entity.Type, scopeName, errs)
	case ast.ScopeTypeIn:
		v.checkEntityType(s.Entity.Type, scopeName, errs)
	case ast.ScopeTypeIs:
		v.checkEntityTypeStrict(s.Type, scopeName, errs)
	case ast.ScopeTypeIsIn:
		v.checkEntityTypeStrict(s.Type, scopeName, errs)
	}
}

// checkEntityType validates an entity type, allowing action types as special case.
func (v *Validator) checkEntityType(t types.EntityType, scopeName string, errs *[]string) {
	if _, ok := v.entityTypes[t]; !ok && !v.isActionEntityType(t) {
		*errs = append(*errs, fmt.Sprintf("%s scope references unknown entity type: %s", scopeName, t))
	}
}

// checkEntityTypeStrict validates an entity type without special cases.
func (v *Validator) checkEntityTypeStrict(t types.EntityType, scopeName string, errs *[]string) {
	if _, ok := v.entityTypes[t]; !ok {
		*errs = append(*errs, fmt.Sprintf("%s scope references unknown entity type: %s", scopeName, t))
	}
}

// validateActionScope validates action scope.
func (v *Validator) validateActionScope(scope ast.IsScopeNode, errs *[]string) {
	switch s := scope.(type) {
	case ast.ScopeTypeEq:
		if _, ok := v.actionTypes[s.Entity]; !ok {
			*errs = append(*errs, fmt.Sprintf("action scope references unknown action: %s", s.Entity))
		}
	case ast.ScopeTypeIn:
		// Action 'in' might reference an action group, which may not be explicitly defined.
		// This is allowed in Cedar.
	case ast.ScopeTypeInSet:
		for _, entity := range s.Entities {
			if _, ok := v.actionTypes[entity]; !ok {
				*errs = append(*errs, fmt.Sprintf("action scope references unknown action: %s", entity))
			}
		}
	}
}

// validateActionAppliesTo checks that principal and resource types are allowed for the action
func (v *Validator) validateActionAppliesTo(policyAST *ast.Policy, errs *[]string) {
	actionInfo := v.getActionInfo(policyAST.Action)
	if actionInfo == nil {
		return
	}

	v.checkScopeTypeAllowed(policyAST.Principal, actionInfo.PrincipalTypes, "principal", errs)
	v.checkScopeTypeAllowed(policyAST.Resource, actionInfo.ResourceTypes, "resource", errs)
}

// getActionInfo extracts ActionTypeInfo from an action scope if available.
func (v *Validator) getActionInfo(scope ast.IsScopeNode) *ActionTypeInfo {
	if s, ok := scope.(ast.ScopeTypeEq); ok {
		if info, ok := v.actionTypes[s.Entity]; ok {
			return info
		}
	}
	return nil
}

// checkScopeTypeAllowed validates that a scope's entity type is in the allowed list.
func (v *Validator) checkScopeTypeAllowed(scope ast.IsScopeNode, allowed []types.EntityType, scopeName string, errs *[]string) {
	if len(allowed) == 0 {
		return
	}

	entityType := v.extractScopeType(scope)
	if entityType == "" {
		return
	}

	if !v.typeInList(entityType, allowed) {
		*errs = append(*errs, fmt.Sprintf("%s type %s is not allowed for this action (allowed: %v)", scopeName, entityType, allowed))
	}
}

// extractScopeType extracts the entity type from a scope node.
func (v *Validator) extractScopeType(scope ast.IsScopeNode) types.EntityType {
	switch s := scope.(type) {
	case ast.ScopeTypeEq:
		return s.Entity.Type
	case ast.ScopeTypeIs:
		return s.Type
	case ast.ScopeTypeIsIn:
		return s.Type
	}
	return ""
}
