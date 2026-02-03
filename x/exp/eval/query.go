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
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
)

// QueryResult represents the result of a policy query operation.
// It describes which values would satisfy the policy constraints.
type QueryResult struct {
	// Decision indicates whether the query found any satisfying values.
	// Allow means at least one value was found that would be permitted.
	// Deny means no values were found, or all values would be denied.
	Decision types.Decision

	// Definite is true when the result is conclusive.
	// False means more information may be needed (residual policies exist).
	Definite bool

	// SatisfyingValues contains specific values that satisfy the query.
	// For QueryPrincipals, these are EntityUIDs of principals.
	// For QueryResources, these are EntityUIDs of resources.
	// For QueryActions, these are EntityUIDs of actions.
	// Empty if the query returns "all" or "none".
	SatisfyingValues []types.EntityUID

	// All is true when all possible values satisfy the query.
	// When true, SatisfyingValues will be empty.
	All bool

	// Constraints contains residual constraints that couldn't be fully resolved.
	// These describe conditions that must be met for additional values to satisfy.
	Constraints []QueryConstraint
}

// QueryConstraint represents a constraint extracted from residual policies.
type QueryConstraint struct {
	// Kind describes the type of constraint.
	Kind ConstraintKind

	// Entity is the target entity for Eq, In, Is constraints.
	Entity types.EntityUID

	// EntityType is the type for Is constraints.
	EntityType types.EntityType

	// Entities is a set of entities for InSet constraints.
	Entities []types.EntityUID
}

// ConstraintKind describes types of constraints.
type ConstraintKind int

const (
	// ConstraintEq means the value must equal a specific entity.
	ConstraintEq ConstraintKind = iota

	// ConstraintIn means the value must be in the entity's ancestors.
	ConstraintIn

	// ConstraintIs means the value must be of a specific type.
	ConstraintIs

	// ConstraintIsIn means the value must be of a type and in ancestors.
	ConstraintIsIn

	// ConstraintInSet means the value must be one of a set of entities.
	ConstraintInSet
)

// QueryPrincipals finds which principals would be permitted to perform
// the given action on the given resource.
//
// This performs partial evaluation with the principal as a variable,
// then analyzes the residual policies to determine:
// - Specific principals that would definitely be allowed
// - Whether all principals would be allowed
// - Any constraints that must be satisfied
//
// Example:
//
//	result := eval.QueryPrincipals(policies, entities,
//	    types.NewEntityUID("Action", "read"),
//	    types.NewEntityUID("Document", "report.pdf"),
//	    types.Record{})
//	if result.All {
//	    // Any principal can read this document
//	} else if len(result.SatisfyingValues) > 0 {
//	    // These specific principals can read
//	}
func QueryPrincipals(
	policies map[types.PolicyID]*ast.Policy,
	entities types.EntityMap,
	action types.EntityUID,
	resource types.EntityUID,
	context types.Record,
) *QueryResult {
	env := Env{
		Principal: Variable("principal"),
		Action:    action,
		Resource:  resource,
		Context:   context,
		Entities:  entities,
	}

	residuals := PartialPolicySet(env, policies)
	return analyzeQueryResult(residuals, "principal")
}

// QueryResources finds which resources the given principal can access
// with the given action.
//
// Example:
//
//	result := eval.QueryResources(policies, entities,
//	    types.NewEntityUID("User", "alice"),
//	    types.NewEntityUID("Action", "read"),
//	    types.Record{})
//	for _, resource := range result.SatisfyingValues {
//	    // alice can read this resource
//	}
func QueryResources(
	policies map[types.PolicyID]*ast.Policy,
	entities types.EntityMap,
	principal types.EntityUID,
	action types.EntityUID,
	context types.Record,
) *QueryResult {
	env := Env{
		Principal: principal,
		Action:    action,
		Resource:  Variable("resource"),
		Context:   context,
		Entities:  entities,
	}

	residuals := PartialPolicySet(env, policies)
	return analyzeQueryResult(residuals, "resource")
}

// QueryActions finds which actions the given principal can perform
// on the given resource.
//
// Example:
//
//	result := eval.QueryActions(policies, entities,
//	    types.NewEntityUID("User", "alice"),
//	    types.NewEntityUID("Document", "report.pdf"),
//	    types.Record{})
//	for _, action := range result.SatisfyingValues {
//	    // alice can perform this action on the document
//	}
func QueryActions(
	policies map[types.PolicyID]*ast.Policy,
	entities types.EntityMap,
	principal types.EntityUID,
	resource types.EntityUID,
	context types.Record,
) *QueryResult {
	env := Env{
		Principal: principal,
		Action:    Variable("action"),
		Resource:  resource,
		Context:   context,
		Entities:  entities,
	}

	residuals := PartialPolicySet(env, policies)
	return analyzeQueryResult(residuals, "action")
}

// analyzeQueryResult analyzes residual policies to determine query results.
func analyzeQueryResult(residuals *ResidualSet, varName string) *QueryResult {
	result := &QueryResult{
		Decision: types.Deny, // Default to deny
		Definite: true,
	}

	// Check for definite forbids first
	if hasDefiniteForbid(residuals) {
		return result
	}

	// Process permit policies
	satisfying, allPermitted, hasVariable := processPermitPolicies(residuals, varName, result)

	// Check if any forbid is variable (could match)
	if hasVariableForbid(residuals) {
		result.Definite = false
	}

	// Build final result
	buildFinalResult(result, satisfying, allPermitted, hasVariable)
	return result
}

// hasDefiniteForbid checks if there's a definite forbid in the residuals.
func hasDefiniteForbid(residuals *ResidualSet) bool {
	for _, f := range residuals.Forbids {
		if f.Kind == ResidualTrue {
			return true
		}
	}
	return false
}

// hasVariableForbid checks if any forbid contains a variable.
func hasVariableForbid(residuals *ResidualSet) bool {
	for _, f := range residuals.Forbids {
		if f.Kind == ResidualVariable {
			return true
		}
	}
	return false
}

// processPermitPolicies processes permit policies and extracts satisfying values.
func processPermitPolicies(residuals *ResidualSet, varName string, result *QueryResult) (map[types.EntityUID]bool, bool, bool) {
	satisfying := make(map[types.EntityUID]bool)
	allPermitted := false
	hasVariable := false

	for _, p := range residuals.Permits {
		switch p.Kind {
		case ResidualTrue:
			allPermitted = true
		case ResidualVariable:
			hasVariable = true
			processVariablePermit(p, varName, result, satisfying)
		}
	}
	return satisfying, allPermitted, hasVariable
}

// processVariablePermit processes a permit policy containing variables.
func processVariablePermit(p ResidualPolicy, varName string, result *QueryResult, satisfying map[types.EntityUID]bool) {
	constraints := extractPolicyConstraints(p.Policy, varName)
	result.Constraints = append(result.Constraints, constraints...)

	values := extractScopeValues(p.Policy, varName)
	for _, v := range values {
		satisfying[v] = true
	}
}

// buildFinalResult builds the final query result based on collected data.
func buildFinalResult(result *QueryResult, satisfying map[types.EntityUID]bool, allPermitted, hasVariable bool) {
	if allPermitted {
		result.Decision = types.Allow
		result.All = true
		return
	}
	if len(satisfying) > 0 {
		result.Decision = types.Allow
		for v := range satisfying {
			result.SatisfyingValues = append(result.SatisfyingValues, v)
		}
		return
	}
	if hasVariable && len(result.Constraints) > 0 {
		result.Definite = false
	}
}

// extractPolicyConstraints extracts constraints from a policy for a variable.
func extractPolicyConstraints(p *ast.Policy, varName string) []QueryConstraint {
	if p == nil {
		return nil
	}

	var constraints []QueryConstraint

	// Extract scope constraints
	switch varName {
	case "principal":
		constraints = append(constraints, extractScopeConstraints(p.Principal)...)
	case "action":
		constraints = append(constraints, extractActionScopeConstraints(p.Action)...)
	case "resource":
		constraints = append(constraints, extractScopeConstraints(p.Resource)...)
	}

	return constraints
}

// extractScopeConstraints extracts constraints from a principal/resource scope.
func extractScopeConstraints(scope ast.IsScopeNode) []QueryConstraint {
	switch s := scope.(type) {
	case ast.ScopeTypeAll:
		// No constraint - all values match
		return nil
	case ast.ScopeTypeEq:
		return []QueryConstraint{{
			Kind:   ConstraintEq,
			Entity: s.Entity,
		}}
	case ast.ScopeTypeIn:
		return []QueryConstraint{{
			Kind:   ConstraintIn,
			Entity: s.Entity,
		}}
	case ast.ScopeTypeIs:
		return []QueryConstraint{{
			Kind:       ConstraintIs,
			EntityType: s.Type,
		}}
	case ast.ScopeTypeIsIn:
		return []QueryConstraint{{
			Kind:       ConstraintIsIn,
			EntityType: s.Type,
			Entity:     s.Entity,
		}}
	}
	return nil
}

// extractActionScopeConstraints extracts constraints from an action scope.
func extractActionScopeConstraints(scope ast.IsActionScopeNode) []QueryConstraint {
	switch s := scope.(type) {
	case ast.ScopeTypeAll:
		return nil
	case ast.ScopeTypeEq:
		return []QueryConstraint{{
			Kind:   ConstraintEq,
			Entity: s.Entity,
		}}
	case ast.ScopeTypeIn:
		return []QueryConstraint{{
			Kind:   ConstraintIn,
			Entity: s.Entity,
		}}
	case ast.ScopeTypeInSet:
		return []QueryConstraint{{
			Kind:     ConstraintInSet,
			Entities: s.Entities,
		}}
	}
	return nil
}

// extractScopeValues extracts specific EntityUID values from a policy scope.
func extractScopeValues(p *ast.Policy, varName string) []types.EntityUID {
	if p == nil {
		return nil
	}

	var values []types.EntityUID

	switch varName {
	case "principal":
		switch s := p.Principal.(type) {
		case ast.ScopeTypeEq:
			values = append(values, s.Entity)
		}
	case "action":
		switch s := p.Action.(type) {
		case ast.ScopeTypeEq:
			values = append(values, s.Entity)
		case ast.ScopeTypeInSet:
			values = append(values, s.Entities...)
		}
	case "resource":
		switch s := p.Resource.(type) {
		case ast.ScopeTypeEq:
			values = append(values, s.Entity)
		}
	}

	return values
}

// QueryDecision performs a full query to determine if a specific request
// would be allowed, returning detailed information about which policies
// contributed to the decision.
//
// This is similar to a standard IsAuthorized but uses partial evaluation
// to provide more detailed analysis of the decision path.
func QueryDecision(
	policies map[types.PolicyID]*ast.Policy,
	entities types.EntityMap,
	principal types.EntityUID,
	action types.EntityUID,
	resource types.EntityUID,
	context types.Record,
) *QueryDecisionResult {
	env := Env{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   context,
		Entities:  entities,
	}

	residuals := PartialPolicySet(env, policies)

	result := &QueryDecisionResult{
		Decision: types.Deny,
	}

	// Check forbids
	for _, f := range residuals.Forbids {
		if f.Kind == ResidualTrue {
			result.Decision = types.Deny
			result.DeterminingPolicies = append(result.DeterminingPolicies, f.PolicyID)
			return result
		}
		if f.Kind == ResidualError {
			result.ErroringPolicies = append(result.ErroringPolicies, f.PolicyID)
		}
	}

	// Check permits
	for _, p := range residuals.Permits {
		if p.Kind == ResidualTrue {
			result.Decision = types.Allow
			result.DeterminingPolicies = append(result.DeterminingPolicies, p.PolicyID)
		}
		if p.Kind == ResidualError {
			result.ErroringPolicies = append(result.ErroringPolicies, p.PolicyID)
		}
	}

	return result
}

// QueryDecisionResult contains detailed information about an authorization decision.
type QueryDecisionResult struct {
	// Decision is the authorization outcome.
	Decision types.Decision

	// DeterminingPolicies lists policies that contributed to the decision.
	DeterminingPolicies []types.PolicyID

	// ErroringPolicies lists policies that encountered errors during evaluation.
	ErroringPolicies []types.PolicyID
}
