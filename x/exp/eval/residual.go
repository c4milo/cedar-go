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
	"slices"

	"github.com/cedar-policy/cedar-go/internal/mapset"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
)

// ResidualKind describes the state of a partially evaluated policy.
type ResidualKind int

const (
	// ResidualTrue indicates the policy condition evaluated to true.
	// For permit policies, this means the policy would allow the request.
	// For forbid policies, this means the policy would deny the request.
	ResidualTrue ResidualKind = iota

	// ResidualFalse indicates the policy condition evaluated to false.
	// The policy will not affect the authorization decision.
	ResidualFalse

	// ResidualVariable indicates the policy contains unresolved variables
	// and cannot be fully evaluated until those variables are bound.
	ResidualVariable

	// ResidualError indicates an error occurred during evaluation.
	// The error is captured in the policy's conditions.
	ResidualError
)

func (k ResidualKind) String() string {
	switch k {
	case ResidualTrue:
		return "true"
	case ResidualFalse:
		return "false"
	case ResidualVariable:
		return "variable"
	case ResidualError:
		return "error"
	default:
		return "unknown"
	}
}

// ResidualPolicy represents a partially evaluated policy with its classification.
type ResidualPolicy struct {
	// PolicyID is the identifier of the original policy.
	PolicyID types.PolicyID

	// Policy is the partially evaluated policy.
	// For ResidualFalse, this may be nil.
	Policy *ast.Policy

	// Kind indicates the evaluation state of the policy.
	Kind ResidualKind

	// Variables contains the names of unresolved variables in the policy.
	// Only populated when Kind is ResidualVariable.
	Variables []types.String

	// Error contains the evaluation error message.
	// Only populated when Kind is ResidualError.
	Error string
}

// ResidualSet contains the results of partial evaluation over a policy set.
type ResidualSet struct {
	// Permits contains residual permit policies.
	Permits []ResidualPolicy

	// Forbids contains residual forbid policies.
	Forbids []ResidualPolicy
}

// PartialPolicySet partially evaluates a set of policies in the given environment.
// It returns a ResidualSet containing the classification of each policy.
//
// Policies that evaluate to false are marked as ResidualFalse and excluded
// from further consideration. Policies with unresolved variables are marked
// as ResidualVariable. Policies that encounter errors are marked as ResidualError.
//
// Example:
//
//	env := eval.Env{
//	    Principal: eval.Variable("principal"),
//	    Action:    types.NewEntityUID("Action", "read"),
//	    Resource:  types.NewEntityUID("Resource", "doc1"),
//	    Context:   types.Record{},
//	    Entities:  entities,
//	}
//	residuals := eval.PartialPolicySet(env, policies)
//	for _, r := range residuals.Permits {
//	    switch r.Kind {
//	    case eval.ResidualTrue:
//	        // Policy definitely permits
//	    case eval.ResidualVariable:
//	        // Policy needs more information
//	    }
//	}
func PartialPolicySet(env Env, policies map[types.PolicyID]*ast.Policy) *ResidualSet {
	result := &ResidualSet{}

	for id, policy := range policies {
		residual, keep := PartialPolicy(env, policy)

		rp := ResidualPolicy{
			PolicyID: id,
			Policy:   residual,
		}

		if !keep {
			rp.Kind = ResidualFalse
		} else {
			rp.Kind = classifyResidual(residual)
			switch rp.Kind {
			case ResidualVariable:
				rp.Variables = findPolicyVariables(residual)
			case ResidualError:
				rp.Error = extractPolicyError(residual)
			}
		}

		if policy.Effect == ast.EffectPermit {
			result.Permits = append(result.Permits, rp)
		} else {
			result.Forbids = append(result.Forbids, rp)
		}
	}

	return result
}

// classifyResidual determines the kind of a residual policy.
func classifyResidual(p *ast.Policy) ResidualKind {
	if p == nil {
		return ResidualFalse
	}

	if scopeNotResolved(p.Principal) || scopeNotResolved(p.Action) || scopeNotResolved(p.Resource) {
		return ResidualVariable
	}

	if len(p.Conditions) == 0 {
		return ResidualTrue
	}

	for _, cond := range p.Conditions {
		kind := classifyCondition(cond)
		if kind != ResidualTrue {
			return kind
		}
	}

	return ResidualTrue
}

// classifyCondition classifies a single condition.
func classifyCondition(cond ast.ConditionType) ResidualKind {
	if _, ok := ToPartialError(cond.Body); ok {
		return ResidualError
	}

	if v, ok := cond.Body.(ast.NodeValue); ok {
		if b, ok := v.Value.(types.Boolean); ok {
			if bool(b) != bool(cond.Condition) {
				return ResidualFalse
			}
			return ResidualTrue
		}
	}

	if hasVariables(cond.Body) {
		return ResidualVariable
	}

	return ResidualTrue
}

// scopeNotResolved checks if a scope wasn't fully resolved to ScopeTypeAll.
func scopeNotResolved(scope ast.IsScopeNode) bool {
	_, ok := scope.(ast.ScopeTypeAll)
	return !ok
}

// hasVariables checks if an AST node contains any variable references.
func hasVariables(n ast.IsNode) bool {
	if n == nil {
		return false
	}

	switch v := n.(type) {
	case ast.NodeTypeVariable:
		return true
	case ast.NodeValue:
		return valueHasVariables(v.Value)
	case ast.NodeTypeIfThenElse:
		return hasVariables(v.If) || hasVariables(v.Then) || hasVariables(v.Else)
	case ast.NodeTypeExtensionCall:
		return slices.ContainsFunc(v.Args, hasVariables)
	case ast.NodeTypeRecord:
		return slices.ContainsFunc(v.Elements, func(e ast.RecordElementNode) bool {
			return hasVariables(e.Value)
		})
	case ast.NodeTypeSet:
		return slices.ContainsFunc(v.Elements, hasVariables)
	default:
		return hasVariablesInChildren(n)
	}
}

// hasVariablesInChildren checks child nodes for variables using the node children helper.
func hasVariablesInChildren(n ast.IsNode) bool {
	return slices.ContainsFunc(getNodeChildren(n), hasVariables)
}

// getNodeChildren returns the child nodes of an AST node.
func getNodeChildren(n ast.IsNode) []ast.IsNode {
	switch v := n.(type) {
	// Unary nodes
	case ast.NodeTypeAccess:
		return []ast.IsNode{v.Arg}
	case ast.NodeTypeHas:
		return []ast.IsNode{v.Arg}
	case ast.NodeTypeLike:
		return []ast.IsNode{v.Arg}
	case ast.NodeTypeNegate:
		return []ast.IsNode{v.Arg}
	case ast.NodeTypeNot:
		return []ast.IsNode{v.Arg}
	case ast.NodeTypeIsEmpty:
		return []ast.IsNode{v.Arg}
	case ast.NodeTypeIs:
		return []ast.IsNode{v.Left}
	// Tag nodes
	case ast.NodeTypeGetTag, ast.NodeTypeHasTag:
		return getTagNodeChildren(v)
	// IsIn node
	case ast.NodeTypeIsIn:
		return []ast.IsNode{v.Left, v.Entity}
	// Container nodes
	case ast.NodeTypeIfThenElse:
		return []ast.IsNode{v.If, v.Then, v.Else}
	case ast.NodeTypeExtensionCall:
		return v.Args
	case ast.NodeTypeRecord:
		return getRecordChildren(v)
	case ast.NodeTypeSet:
		return v.Elements
	default:
		return getBinaryNodeChildren(n)
	}
}

// getRecordChildren extracts child nodes from a record node.
func getRecordChildren(r ast.NodeTypeRecord) []ast.IsNode {
	children := make([]ast.IsNode, 0, len(r.Elements))
	for _, elem := range r.Elements {
		children = append(children, elem.Value)
	}
	return children
}

// getTagNodeChildren handles tag node types.
func getTagNodeChildren(n ast.IsNode) []ast.IsNode {
	switch v := n.(type) {
	case ast.NodeTypeGetTag:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeHasTag:
		return []ast.IsNode{v.Left, v.Right}
	}
	return nil
}

// getBinaryNodeChildren returns children for binary operator nodes.
func getBinaryNodeChildren(n ast.IsNode) []ast.IsNode {
	switch v := n.(type) {
	case ast.NodeTypeIn:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeAnd:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeOr:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeEquals:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeNotEquals:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeGreaterThan:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeGreaterThanOrEqual:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeLessThan:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeLessThanOrEqual:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeSub:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeAdd:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeMult:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeContains:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeContainsAll:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeContainsAny:
		return []ast.IsNode{v.Left, v.Right}
	}
	return nil
}

// valueHasVariables checks if a value contains variable references.
func valueHasVariables(v types.Value) bool {
	if ent, ok := v.(types.EntityUID); ok {
		_, isVar := ToVariable(ent)
		return isVar
	}
	switch t := v.(type) {
	case types.Record:
		for val := range t.Values() {
			if valueHasVariables(val) {
				return true
			}
		}
	case types.Set:
		for val := range t.All() {
			if valueHasVariables(val) {
				return true
			}
		}
	}
	return false
}

// findPolicyVariables extracts all variable names from a policy.
func findPolicyVariables(p *ast.Policy) []types.String {
	var found mapset.MapSet[types.String]

	if scopeNotResolved(p.Principal) {
		found.Add("principal")
	}
	if scopeNotResolved(p.Action) {
		found.Add("action")
	}
	if scopeNotResolved(p.Resource) {
		found.Add("resource")
	}

	for _, cond := range p.Conditions {
		findNodeVariables(&found, cond.Body)
	}

	result := make([]types.String, 0, found.Len())
	for v := range found.All() {
		result = append(result, v)
	}
	return result
}

// findNodeVariables recursively finds all variables in an AST node.
func findNodeVariables(found *mapset.MapSet[types.String], n ast.IsNode) {
	if n == nil {
		return
	}

	switch v := n.(type) {
	case ast.NodeTypeVariable:
		found.Add(types.String(v.Name))
	case ast.NodeValue:
		findValueVariables(found, v.Value)
	default:
		findChildNodeVariables(found, n)
	}
}

// findChildNodeVariables recursively processes child nodes to find variables.
func findChildNodeVariables(found *mapset.MapSet[types.String], n ast.IsNode) {
	for _, child := range getNodeChildren(n) {
		findNodeVariables(found, child)
	}
}

// findValueVariables recursively finds all variables in a value.
func findValueVariables(found *mapset.MapSet[types.String], v types.Value) {
	if ent, ok := v.(types.EntityUID); ok {
		if name, isVar := ToVariable(ent); isVar {
			found.Add(name)
		}
		return
	}
	switch t := v.(type) {
	case types.Record:
		for val := range t.Values() {
			findValueVariables(found, val)
		}
	case types.Set:
		for val := range t.All() {
			findValueVariables(found, val)
		}
	}
}

// extractPolicyError extracts the error message from a policy with errors.
func extractPolicyError(p *ast.Policy) string {
	for _, cond := range p.Conditions {
		if err, ok := ToPartialError(cond.Body); ok {
			return err.Error()
		}
	}
	return ""
}

// MustDecide returns true if the ResidualSet can make a definitive authorization decision.
func (rs *ResidualSet) MustDecide() bool {
	if rs.hasDefiniteForbid() {
		return true
	}
	return rs.hasDefinitePermit() && !rs.hasPotentialForbid()
}

func (rs *ResidualSet) hasDefiniteForbid() bool {
	for _, f := range rs.Forbids {
		if f.Kind == ResidualTrue {
			return true
		}
	}
	return false
}

func (rs *ResidualSet) hasDefinitePermit() bool {
	for _, p := range rs.Permits {
		if p.Kind == ResidualTrue {
			return true
		}
	}
	return false
}

func (rs *ResidualSet) hasPotentialForbid() bool {
	for _, f := range rs.Forbids {
		if f.Kind == ResidualVariable || f.Kind == ResidualError {
			return true
		}
	}
	return false
}

// Decision returns the authorization decision if MustDecide() is true.
func (rs *ResidualSet) Decision() types.Decision {
	for _, f := range rs.Forbids {
		if f.Kind == ResidualTrue {
			return types.Deny
		}
	}
	for _, p := range rs.Permits {
		if p.Kind == ResidualTrue {
			return types.Allow
		}
	}
	panic("Decision called when MustDecide() is false")
}

// TruePermits returns all permit policies that are definitely true.
func (rs *ResidualSet) TruePermits() []ResidualPolicy {
	return rs.filterByKind(rs.Permits, ResidualTrue)
}

// TrueForbids returns all forbid policies that are definitely true.
func (rs *ResidualSet) TrueForbids() []ResidualPolicy {
	return rs.filterByKind(rs.Forbids, ResidualTrue)
}

// VariablePermits returns all permit policies containing unresolved variables.
func (rs *ResidualSet) VariablePermits() []ResidualPolicy {
	return rs.filterByKind(rs.Permits, ResidualVariable)
}

// VariableForbids returns all forbid policies containing unresolved variables.
func (rs *ResidualSet) VariableForbids() []ResidualPolicy {
	return rs.filterByKind(rs.Forbids, ResidualVariable)
}

func (rs *ResidualSet) filterByKind(policies []ResidualPolicy, kind ResidualKind) []ResidualPolicy {
	var result []ResidualPolicy
	for _, p := range policies {
		if p.Kind == kind {
			result = append(result, p)
		}
	}
	return result
}

// AllVariables returns all unique variable names across all residual policies.
func (rs *ResidualSet) AllVariables() []types.String {
	var found mapset.MapSet[types.String]
	for _, p := range rs.Permits {
		for _, v := range p.Variables {
			found.Add(v)
		}
	}
	for _, f := range rs.Forbids {
		for _, v := range f.Variables {
			found.Add(v)
		}
	}
	result := make([]types.String, 0, found.Len())
	for v := range found.All() {
		result = append(result, v)
	}
	return result
}

// Ignore returns a value marker that indicates this part of the request should be ignored
// during partial evaluation. See batch.Ignore for the primary use case.
func Ignore() types.Value {
	return ignoreValue()
}

// IsIgnore checks if a value is the Ignore marker.
func IsIgnore(v types.Value) bool {
	return isIgnoreValue(v)
}
