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

// hasImpossibleCondition checks if a policy has conditions that make it
// semantically impossible to satisfy. This includes:
// - when { false } - a when clause that is always false
// - unless { true } - an unless clause that is always true
// This also handles constant expressions like `true || !true` which evaluate to `true`.
func (v *Validator) hasImpossibleCondition(policy *ast.Policy) bool {
	return slices.ContainsFunc(policy.Conditions, v.isConditionImpossible)
}

// isConditionImpossible checks if a single condition is semantically impossible.
func (v *Validator) isConditionImpossible(cond ast.ConditionType) bool {
	boolVal, isConst := v.evaluateConstantBool(cond.Body)
	if !isConst {
		return false
	}
	// when { false } -> impossible
	// unless { true } -> impossible
	return (cond.Condition == ast.ConditionWhen && !boolVal) ||
		(cond.Condition == ast.ConditionUnless && boolVal)
}

// evaluateConstantBool attempts to evaluate an AST node as a constant boolean expression.
// Returns the boolean value and true if the expression is a constant, or false, false otherwise.
func (v *Validator) evaluateConstantBool(node ast.IsNode) (bool, bool) {
	switch n := node.(type) {
	case ast.NodeValue:
		return v.evaluateConstantValue(n)
	case ast.NodeTypeNot:
		return v.evaluateConstantNot(n)
	case ast.NodeTypeAnd:
		return v.evaluateConstantAnd(n)
	case ast.NodeTypeOr:
		return v.evaluateConstantOr(n)
	case ast.NodeTypeIfThenElse:
		return v.evaluateConstantIfThenElse(n)
	default:
		return false, false
	}
}

// evaluateConstantValue extracts a boolean from a literal value node.
func (v *Validator) evaluateConstantValue(n ast.NodeValue) (bool, bool) {
	if boolVal, ok := n.Value.(types.Boolean); ok {
		return bool(boolVal), true
	}
	return false, false
}

// evaluateConstantNot evaluates a negation of a constant boolean.
func (v *Validator) evaluateConstantNot(n ast.NodeTypeNot) (bool, bool) {
	if val, isConst := v.evaluateConstantBool(n.Arg); isConst {
		return !val, true
	}
	return false, false
}

// evaluateConstantAnd evaluates an AND operation with short-circuit semantics.
func (v *Validator) evaluateConstantAnd(n ast.NodeTypeAnd) (bool, bool) {
	leftVal, leftConst := v.evaluateConstantBool(n.Left)
	rightVal, rightConst := v.evaluateConstantBool(n.Right)

	if leftConst && rightConst {
		return leftVal && rightVal, true
	}
	// Short-circuit: false && anything = false
	if leftConst && !leftVal {
		return false, true
	}
	if rightConst && !rightVal {
		return false, true
	}
	return false, false
}

// evaluateConstantOr evaluates an OR operation with short-circuit semantics.
func (v *Validator) evaluateConstantOr(n ast.NodeTypeOr) (bool, bool) {
	leftVal, leftConst := v.evaluateConstantBool(n.Left)
	rightVal, rightConst := v.evaluateConstantBool(n.Right)

	if leftConst && rightConst {
		return leftVal || rightVal, true
	}
	// Short-circuit: true || anything = true
	if leftConst && leftVal {
		return true, true
	}
	if rightConst && rightVal {
		return true, true
	}
	return false, false
}

// evaluateConstantIfThenElse evaluates a conditional with constant condition.
func (v *Validator) evaluateConstantIfThenElse(n ast.NodeTypeIfThenElse) (bool, bool) {
	condVal, condConst := v.evaluateConstantBool(n.If)
	if !condConst {
		return false, false
	}
	if condVal {
		return v.evaluateConstantBool(n.Then)
	}
	return v.evaluateConstantBool(n.Else)
}

// isSchemaEmpty returns true if the schema has no valid environments.
// A schema is "empty" for policy validation if no action has a valid appliesTo
// configuration (non-empty principalTypes AND resourceTypes).
// This matches Lean's behavior where policies are "impossible" if there are
// no valid (principal, action, resource) combinations.
func (v *Validator) isSchemaEmpty() bool {
	for _, info := range v.actionTypes {
		// An action has a valid environment if it has at least one principal type
		// AND at least one resource type in its appliesTo
		if len(info.PrincipalTypes) > 0 && len(info.ResourceTypes) > 0 {
			return false // Found at least one valid environment
		}
	}
	return true // No valid environments
}

// validateEntity validates a single entity.
func (v *Validator) validateEntity(uid types.EntityUID, entity types.Entity) []EntityError {
	entityInfo, ok := v.entityTypes[uid.Type]
	if !ok {
		return v.handleUnknownEntityType(uid)
	}

	var errs []EntityError
	errs = append(errs, v.validateEntityAttributes(uid, entity, entityInfo)...)
	errs = append(errs, v.validateUndeclaredAttributes(uid, entity, entityInfo)...)
	errs = append(errs, v.validateParentRelationships(uid, entity, entityInfo)...)
	return errs
}

// handleUnknownEntityType handles validation when entity type is not in schema.
func (v *Validator) handleUnknownEntityType(uid types.EntityUID) []EntityError {
	if v.isActionEntityType(uid.Type) {
		return nil // Action entities are handled differently
	}
	return []EntityError{{
		EntityUID: uid,
		Message:   fmt.Sprintf("entity type %s is not defined in schema", uid.Type),
	}}
}

// validateEntityAttributes validates all declared attributes of an entity.
func (v *Validator) validateEntityAttributes(uid types.EntityUID, entity types.Entity, info *EntityTypeInfo) []EntityError {
	var errs []EntityError
	for attrName, attrType := range info.Attributes {
		if err := v.validateEntityAttribute(uid, entity, attrName, attrType); err != nil {
			errs = append(errs, *err)
		}
	}
	return errs
}

// validateEntityAttribute validates a single attribute of an entity.
func (v *Validator) validateEntityAttribute(uid types.EntityUID, entity types.Entity, attrName string, attrType AttributeType) *EntityError {
	attrVal, exists := entity.Attributes.Get(types.String(attrName))
	if !exists {
		if attrType.Required {
			return &EntityError{EntityUID: uid, Message: fmt.Sprintf("required attribute %s is missing", attrName)}
		}
		return nil
	}
	if err := v.validateValue(attrVal, attrType.Type); err != nil {
		return &EntityError{EntityUID: uid, Message: fmt.Sprintf("attribute %s: %v", attrName, err)}
	}
	return nil
}

// validateUndeclaredAttributes checks for undeclared attributes in strict mode.
func (v *Validator) validateUndeclaredAttributes(uid types.EntityUID, entity types.Entity, info *EntityTypeInfo) []EntityError {
	if !v.strictEntityValidation || info.OpenRecord {
		return nil
	}
	var errs []EntityError
	for attrName := range entity.Attributes.All() {
		if _, declared := info.Attributes[string(attrName)]; !declared {
			errs = append(errs, EntityError{
				EntityUID: uid,
				Message:   fmt.Sprintf("attribute %s is not declared in schema", attrName),
			})
		}
	}
	return errs
}

// validateParentRelationships validates that parent relationships are allowed.
func (v *Validator) validateParentRelationships(uid types.EntityUID, entity types.Entity, info *EntityTypeInfo) []EntityError {
	var errs []EntityError
	for parent := range entity.Parents.All() {
		if !v.typeInList(parent.Type, info.MemberOfTypes) {
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

	if err := v.validateContextAttributes(rec, expected); err != nil {
		return err
	}
	return v.validateContextUndeclaredAttributes(rec, expected)
}

// validateContextAttributes validates all declared context attributes.
func (v *Validator) validateContextAttributes(rec types.Record, expected RecordType) error {
	for attrName, attrType := range expected.Attributes {
		if err := v.validateContextAttribute(rec, attrName, attrType); err != nil {
			return err
		}
	}
	return nil
}

// validateContextAttribute validates a single context attribute.
func (v *Validator) validateContextAttribute(rec types.Record, attrName string, attrType AttributeType) error {
	val, exists := rec.Get(types.String(attrName))
	if !exists {
		if attrType.Required {
			return fmt.Errorf("required context attribute %s is missing", attrName)
		}
		return nil
	}
	if err := v.validateValue(val, attrType.Type); err != nil {
		return fmt.Errorf("context attribute %s: %v", attrName, err)
	}
	return nil
}

// validateContextUndeclaredAttributes checks for undeclared context attributes in strict mode.
func (v *Validator) validateContextUndeclaredAttributes(rec types.Record, expected RecordType) error {
	if !v.strictEntityValidation || expected.OpenRecord {
		return nil
	}
	for attrName := range rec.All() {
		if _, declared := expected.Attributes[string(attrName)]; !declared {
			return fmt.Errorf("context attribute %s is not declared in schema", attrName)
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
		v.validateActionScopeEq(s, errs)
	case ast.ScopeTypeIn:
		// Action 'in' might reference an action group, which may not be explicitly defined.
		// This is allowed in Cedar.
	case ast.ScopeTypeInSet:
		v.validateActionScopeInSet(s, errs)
	}
}

// validateActionScopeEq validates an action == EntityUID scope.
func (v *Validator) validateActionScopeEq(s ast.ScopeTypeEq, errs *[]string) {
	info, ok := v.actionTypes[s.Entity]
	if !ok {
		*errs = append(*errs, fmt.Sprintf("action scope references unknown action: %s", s.Entity))
		return
	}
	if !v.actionHasValidAppliesTo(info) {
		// An action without appliesTo (no principalTypes AND no resourceTypes)
		// makes the policy impossible - Lean rejects with "unknownEntity"
		*errs = append(*errs, fmt.Sprintf("impossiblePolicy: action %s has no valid appliesTo configuration", s.Entity))
	}
}

// validateActionScopeInSet validates an action in [EntityUID, ...] scope.
func (v *Validator) validateActionScopeInSet(s ast.ScopeTypeInSet, errs *[]string) {
	if len(s.Entities) == 0 {
		*errs = append(*errs, "impossiblePolicy: action in empty set can never match")
		return
	}

	allInvalid := true
	for _, entity := range s.Entities {
		info, ok := v.actionTypes[entity]
		if !ok {
			*errs = append(*errs, fmt.Sprintf("action scope references unknown action: %s", entity))
		} else if v.actionHasValidAppliesTo(info) {
			allInvalid = false
		}
	}

	if allInvalid {
		*errs = append(*errs, "impossiblePolicy: no action in set has valid appliesTo configuration")
	}
}

// actionHasValidAppliesTo checks if an action has a valid appliesTo configuration.
// An action is valid if it has at least one principalType AND at least one resourceType.
// Additionally, if the types look like they have a non-empty namespace but empty type name
// (like "Namespace::"), Lean considers this an unknownEntity error.
func (v *Validator) actionHasValidAppliesTo(info *ActionTypeInfo) bool {
	if len(info.PrincipalTypes) == 0 || len(info.ResourceTypes) == 0 {
		return false
	}

	// Check if ALL types in both lists are "malformed" unknown types.
	// A malformed unknown type has the pattern "Namespace::" (non-empty namespace, empty type name).
	// Lean rejects these, but accepts "::" (empty namespace, empty type name).
	if slices.ContainsFunc(info.PrincipalTypes, v.isMalformedUnknownType) {
		// Found a malformed type - check if all types are malformed
		return !v.allTypesMalformed(info.PrincipalTypes, info.ResourceTypes)
	}

	return true
}

// isMalformedUnknownType checks if a type has the pattern "Namespace::" (ends with "::" but has content before).
// This is a type with a non-empty namespace but empty type name, which Lean rejects.
func (v *Validator) isMalformedUnknownType(et types.EntityType) bool {
	s := string(et)
	// Check if it ends with "::" but has something before (not just "::")
	return strings.HasSuffix(s, "::") && len(s) > 2 && !v.isKnownType(et)
}

// allTypesMalformed checks if ALL types in both lists are malformed unknown types.
func (v *Validator) allTypesMalformed(principalTypes, resourceTypes []types.EntityType) bool {
	for _, pt := range principalTypes {
		if !v.isMalformedUnknownType(pt) {
			return false
		}
	}
	for _, rt := range resourceTypes {
		if !v.isMalformedUnknownType(rt) {
			return false
		}
	}
	return true
}

// isKnownType checks if an entity type is defined in the schema or is an action type.
func (v *Validator) isKnownType(et types.EntityType) bool {
	_, ok := v.entityTypes[et]
	return ok || v.isActionEntityType(et)
}

// validateActionAppliesTo checks that principal and resource types are allowed for the action(s).
// For action sets (action in [A, B, C]), the scope must be valid for at least one action.
func (v *Validator) validateActionAppliesTo(policyAST *ast.Policy, errs *[]string) {
	actionInfos := v.getActionInfos(policyAST.Action)
	if len(actionInfos) == 0 {
		return
	}

	if v.hasValidActionMatch(policyAST, actionInfos) {
		return
	}

	v.reportActionAppliesToError(policyAST, actionInfos, errs)
}

// hasValidActionMatch checks if any action supports the policy's principal and resource constraints.
func (v *Validator) hasValidActionMatch(policyAST *ast.Policy, actionInfos []*ActionTypeInfo) bool {
	for _, info := range actionInfos {
		principalOK := v.isScopeTypeSatisfiable(policyAST.Principal, info.PrincipalTypes, "principal")
		resourceOK := v.isScopeTypeSatisfiable(policyAST.Resource, info.ResourceTypes, "resource")
		if principalOK && resourceOK {
			return true
		}
	}
	return false
}

// reportActionAppliesToError reports errors when no action supports the policy constraints.
func (v *Validator) reportActionAppliesToError(policyAST *ast.Policy, actionInfos []*ActionTypeInfo, errs *[]string) {
	principalTypes := v.unionPrincipalTypes(actionInfos)
	resourceTypes := v.unionResourceTypes(actionInfos)

	principalOK := v.isScopeTypeSatisfiable(policyAST.Principal, principalTypes, "principal")
	resourceOK := v.isScopeTypeSatisfiable(policyAST.Resource, resourceTypes, "resource")

	if !principalOK {
		v.checkScopeTypeAllowed(policyAST.Principal, principalTypes, "principal", errs)
	}
	if !resourceOK {
		v.checkScopeTypeAllowed(policyAST.Resource, resourceTypes, "resource", errs)
	}
	if principalOK && resourceOK {
		*errs = append(*errs, "impossiblePolicy: no action supports the combination of principal and resource types in this policy")
	}
}

// getActionInfos extracts ActionTypeInfo(s) from an action scope.
// Returns slice of action infos for single action or action set.
// For ScopeTypeAll (unscoped action), returns all action infos.
func (v *Validator) getActionInfos(scope ast.IsScopeNode) []*ActionTypeInfo {
	switch s := scope.(type) {
	case ast.ScopeTypeAll:
		// For unscoped action (all actions), return all action infos.
		// This enables impossiblePolicy checking against all possible actions.
		var infos []*ActionTypeInfo
		for _, info := range v.actionTypes {
			infos = append(infos, info)
		}
		return infos
	case ast.ScopeTypeEq:
		if info, ok := v.actionTypes[s.Entity]; ok {
			return []*ActionTypeInfo{info}
		}
	case ast.ScopeTypeInSet:
		var infos []*ActionTypeInfo
		for _, entity := range s.Entities {
			if info, ok := v.actionTypes[entity]; ok {
				infos = append(infos, info)
			}
		}
		return infos
	}
	return nil
}

// unionPrincipalTypes returns the union of principal types from multiple action infos.
func (v *Validator) unionPrincipalTypes(infos []*ActionTypeInfo) []types.EntityType {
	seen := make(map[types.EntityType]bool)
	var result []types.EntityType
	for _, info := range infos {
		for _, t := range info.PrincipalTypes {
			if !seen[t] {
				seen[t] = true
				result = append(result, t)
			}
		}
	}
	return result
}

// unionResourceTypes returns the union of resource types from multiple action infos.
func (v *Validator) unionResourceTypes(infos []*ActionTypeInfo) []types.EntityType {
	seen := make(map[types.EntityType]bool)
	var result []types.EntityType
	for _, info := range infos {
		for _, t := range info.ResourceTypes {
			if !seen[t] {
				seen[t] = true
				result = append(result, t)
			}
		}
	}
	return result
}

// isScopeTypeSatisfiable checks if a scope constraint is satisfiable with the given allowed types.
// Returns true if the constraint can be satisfied, false otherwise.
func (v *Validator) isScopeTypeSatisfiable(scope ast.IsScopeNode, allowed []types.EntityType, scopeName string) bool {
	if len(allowed) == 0 {
		return false
	}

	switch s := scope.(type) {
	case ast.ScopeTypeAll:
		return true
	case ast.ScopeTypeEq:
		if v.isActionEntityType(s.Entity.Type) {
			return true
		}
		return v.typeInList(s.Entity.Type, allowed)
	case ast.ScopeTypeIs:
		return v.typeInList(s.Type, allowed)
	case ast.ScopeTypeIsIn:
		return v.typeInList(s.Type, allowed)
	case ast.ScopeTypeIn:
		return v.typeInList(s.Entity.Type, allowed)
	}
	return true // Unknown scope type, assume satisfiable
}

// checkScopeTypeAllowed validates that a scope's entity type is in the allowed list.
func (v *Validator) checkScopeTypeAllowed(scope ast.IsScopeNode, allowed []types.EntityType, scopeName string, errs *[]string) {
	if len(allowed) == 0 {
		return
	}

	switch s := scope.(type) {
	case ast.ScopeTypeEq:
		v.checkScopeTypeEq(s, allowed, scopeName, errs)
	case ast.ScopeTypeIs:
		v.checkScopeTypeIs(s.Type, allowed, scopeName, errs)
	case ast.ScopeTypeIsIn:
		v.checkScopeTypeIs(s.Type, allowed, scopeName, errs)
	case ast.ScopeTypeIn:
		v.checkScopeTypeIn(s, allowed, scopeName, errs)
	}
}

// checkScopeTypeEq validates that an == scope's entity type is allowed.
func (v *Validator) checkScopeTypeEq(s ast.ScopeTypeEq, allowed []types.EntityType, scopeName string, errs *[]string) {
	// Action types (Action::...) are special and always allowed
	if v.isActionEntityType(s.Entity.Type) {
		return
	}
	if !v.typeInList(s.Entity.Type, allowed) {
		*errs = append(*errs, fmt.Sprintf("impossiblePolicy: %s type %s is not allowed for this action (allowed: %v)", scopeName, s.Entity.Type, allowed))
	}
}

// checkScopeTypeIs validates that an is/is-in scope's type is allowed.
func (v *Validator) checkScopeTypeIs(entityType types.EntityType, allowed []types.EntityType, scopeName string, errs *[]string) {
	if !v.typeInList(entityType, allowed) {
		*errs = append(*errs, fmt.Sprintf("impossiblePolicy: %s type %s is not allowed for this action (allowed: %v)", scopeName, entityType, allowed))
	}
}

// checkScopeTypeIn validates that an in scope's entity type is allowed and satisfiable.
func (v *Validator) checkScopeTypeIn(s ast.ScopeTypeIn, allowed []types.EntityType, scopeName string, errs *[]string) {
	// For "principal/resource in Entity::...", we need to check two things:
	//
	// 1. The entity type in the "in" clause must be in the allowed types.
	//    Lean's impossiblePolicy check requires the scope's entity type to be directly
	//    in the allowed list.
	//
	// 2. At least one allowed type must be able to be a descendant of the entity type.
	//    This requires checking memberOfTypes.
	entityType := s.Entity.Type

	if !v.typeInList(entityType, allowed) {
		*errs = append(*errs, fmt.Sprintf("impossiblePolicy: %s in %s::%s is not satisfiable (allowed types: %v)", scopeName, entityType, s.Entity.ID, allowed))
		return
	}

	if !v.canAnyTypeBeDescendantOf(allowed, entityType) {
		*errs = append(*errs, fmt.Sprintf("impossiblePolicy: %s in %s::%s is not satisfiable (no allowed type can be in %s)", scopeName, entityType, s.Entity.ID, entityType))
	}
}

// canAnyTypeBeDescendantOf checks if any type in the list can be a descendant
// of the target type based on memberOfTypes relationships.
// A type T can be a descendant of target if T.MemberOfTypes includes target
// (directly or transitively through the memberOf chain).
func (v *Validator) canAnyTypeBeDescendantOf(typeList []types.EntityType, target types.EntityType) bool {
	for _, t := range typeList {
		if v.canBeDescendantOf(t, target, make(map[types.EntityType]bool)) {
			return true
		}
	}
	return false
}

// canBeDescendantOf checks if sourceType can be a descendant of targetType.
// This checks if sourceType's memberOfTypes (transitively) includes targetType.
func (v *Validator) canBeDescendantOf(sourceType, targetType types.EntityType, visited map[types.EntityType]bool) bool {
	// Avoid infinite loops in case of circular memberOfTypes
	if visited[sourceType] {
		return false
	}
	visited[sourceType] = true

	info := v.entityTypes[sourceType]
	if info == nil {
		return false
	}

	// Check if sourceType can directly be a member of targetType
	for _, memberOf := range info.MemberOfTypes {
		if memberOf == targetType {
			return true
		}
		// Recursively check if memberOf can be a descendant of target
		// This handles chains like: Type3 -> Type2 -> Type1 -> Type0
		if v.canBeDescendantOf(memberOf, targetType, visited) {
			return true
		}
	}

	return false
}
