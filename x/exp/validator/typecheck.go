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
	"maps"
	"slices"

	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
)

// typeContext holds the type environment during type-checking
type typeContext struct {
	v              *Validator
	principalTypes []types.EntityType // Possible types for principal
	resourceTypes  []types.EntityType // Possible types for resource
	actionUID      *types.EntityUID   // Specific action (if known)
	contextType    schema.RecordType  // Context type for the effective actions
	errors         []string
	currentLevel   int // Current attribute dereference level
}

// typecheckPolicy performs full type-checking on a policy
func (v *Validator) typecheckPolicy(p *ast.Policy) []string {
	ctx := &typeContext{
		v: v,
	}

	// Determine the effective types considering all scope constraints.
	// This is important for detecting impossible policies in conditions.
	// For example, if principal == Type0::... and action is "all",
	// we need to find which actions allow Type0 as principal,
	// and use ONLY those actions' resource types.
	effectiveActions := v.getEffectiveActions(p.Principal, p.Action, p.Resource)
	ctx.principalTypes = v.extractEffectivePrincipalTypes(p.Principal, effectiveActions)
	ctx.resourceTypes = v.extractEffectiveResourceTypes(p.Resource, effectiveActions)
	ctx.actionUID = v.extractActionUID(p.Action)
	ctx.contextType = v.extractEffectiveContextType(effectiveActions)

	// Type-check each condition
	for _, cond := range p.Conditions {
		inferredType := ctx.typecheck(cond.Body)

		// Condition must evaluate to Boolean.
		// We allow UnknownType here for cases where the type can't be determined
		// (e.g., action scope is 'all' so context type is unknown).
		// However, UnspecifiedType (attribute with no type in schema) is NOT allowed
		// as a condition - this is a schema error that should be reported.
		if _, isUnspecified := inferredType.(schema.UnspecifiedType); isUnspecified {
			ctx.errors = append(ctx.errors,
				"unexpectedType: condition uses value with unspecified type from schema")
		} else if !isTypeBoolean(inferredType) && !isTypeUnknown(inferredType) {
			ctx.errors = append(ctx.errors,
				fmt.Sprintf("unexpectedType: condition must be boolean, got %s", inferredType))
		}
	}

	return ctx.errors
}

// getEffectiveActions returns the actions that could potentially match all scope constraints.
// This filters out actions that cannot satisfy the principal or resource scope.
func (v *Validator) getEffectiveActions(
	principalScope ast.IsPrincipalScopeNode,
	actionScope ast.IsActionScopeNode,
	resourceScope ast.IsResourceScopeNode,
) []*schema.ActionTypeInfo {
	candidateActions := v.getCandidateActions(actionScope)
	if len(candidateActions) == 0 {
		return nil
	}

	principalFiltered := v.filterByPrincipalScope(candidateActions, principalScope)
	if len(principalFiltered) == 0 {
		return nil
	}

	return v.filterByResourceScope(principalFiltered, resourceScope)
}

// getCandidateActions returns actions matching the action scope.
func (v *Validator) getCandidateActions(actionScope ast.IsActionScopeNode) []*schema.ActionTypeInfo {
	switch a := actionScope.(type) {
	case ast.ScopeTypeAll:
		return v.allActions()
	case ast.ScopeTypeEq:
		if info, ok := v.actionTypes[a.Entity]; ok {
			return []*schema.ActionTypeInfo{info}
		}
	case ast.ScopeTypeInSet:
		return v.actionsInSet(a.Entities)
	}
	return nil
}

// allActions returns all defined actions.
func (v *Validator) allActions() []*schema.ActionTypeInfo {
	var actions []*schema.ActionTypeInfo
	for _, info := range v.actionTypes {
		actions = append(actions, info)
	}
	return actions
}

// actionsInSet returns actions matching the given entity UIDs.
func (v *Validator) actionsInSet(entities []types.EntityUID) []*schema.ActionTypeInfo {
	var actions []*schema.ActionTypeInfo
	for _, entity := range entities {
		if info, ok := v.actionTypes[entity]; ok {
			actions = append(actions, info)
		}
	}
	return actions
}

// filterByPrincipalScope filters actions by principal scope compatibility.
func (v *Validator) filterByPrincipalScope(actions []*schema.ActionTypeInfo, scope ast.IsPrincipalScopeNode) []*schema.ActionTypeInfo {
	principalType := v.extractScopeEntityType(scope)
	var filtered []*schema.ActionTypeInfo
	for _, action := range actions {
		if principalType == "" || v.typeInList(principalType, action.PrincipalTypes) {
			filtered = append(filtered, action)
		}
	}
	return filtered
}

// filterByResourceScope filters actions by resource scope compatibility.
func (v *Validator) filterByResourceScope(actions []*schema.ActionTypeInfo, scope ast.IsResourceScopeNode) []*schema.ActionTypeInfo {
	resourceType := v.extractScopeEntityType(scope)
	var filtered []*schema.ActionTypeInfo
	for _, action := range actions {
		if resourceType == "" || v.typeInList(resourceType, action.ResourceTypes) {
			filtered = append(filtered, action)
		}
	}
	return filtered
}

// extractScopeEntityType extracts the entity type from a scope if it specifies one.
// Returns empty string if the scope doesn't constrain to a specific type.
func (v *Validator) extractScopeEntityType(scope ast.IsScopeNode) types.EntityType {
	switch s := scope.(type) {
	case ast.ScopeTypeEq:
		return s.Entity.Type
	case ast.ScopeTypeIs:
		return s.Type
	case ast.ScopeTypeIsIn:
		return s.Type
	case ast.ScopeTypeIn:
		return s.Entity.Type
	}
	return ""
}

// extractEffectivePrincipalTypes extracts principal types from effective actions.
func (v *Validator) extractEffectivePrincipalTypes(scope ast.IsPrincipalScopeNode, effectiveActions []*schema.ActionTypeInfo) []types.EntityType {
	if len(effectiveActions) == 0 {
		return nil
	}

	// Get union of principal types from effective actions
	typeSet := make(map[types.EntityType]bool)
	for _, action := range effectiveActions {
		for _, pt := range action.PrincipalTypes {
			typeSet[pt] = true
		}
	}
	actionTypes := mapKeysToSlice(typeSet)

	return v.resolveEntityScopeTypes(scope, actionTypes)
}

// extractEffectiveResourceTypes extracts resource types from effective actions.
func (v *Validator) extractEffectiveResourceTypes(scope ast.IsResourceScopeNode, effectiveActions []*schema.ActionTypeInfo) []types.EntityType {
	if len(effectiveActions) == 0 {
		return nil
	}

	// Get union of resource types from effective actions
	typeSet := make(map[types.EntityType]bool)
	for _, action := range effectiveActions {
		for _, rt := range action.ResourceTypes {
			typeSet[rt] = true
		}
	}
	actionTypes := mapKeysToSlice(typeSet)

	return v.resolveEntityScopeTypes(scope, actionTypes)
}

// extractEffectiveContextType extracts the context type from effective actions.
// For multiple actions, computes the INTERSECTION of context attributes.
// An attribute is only available if it exists in ALL actions' context types.
// This ensures accessing context.attr is safe for all possible actions.
//
// Returns:
// - For no effective actions: RecordType{} with nil Attributes (unknown, lenient)
// - For single action: that action's context type (fully known)
// - For multiple actions: intersection of their context attributes
//   - If intersection is empty, returns RecordType with empty (non-nil) Attributes
//   - This means accessing ANY attribute is an attrNotFound error (matches Lean)
func (v *Validator) extractEffectiveContextType(effectiveActions []*schema.ActionTypeInfo) schema.RecordType {
	if len(effectiveActions) == 0 {
		return schema.RecordType{} // Unknown context, be lenient
	}
	if len(effectiveActions) == 1 {
		return effectiveActions[0].Context
	}
	return v.computeContextIntersection(effectiveActions)
}

// computeContextIntersection computes the intersection of context attributes from multiple actions.
func (v *Validator) computeContextIntersection(actions []*schema.ActionTypeInfo) schema.RecordType {
	intersection := copyAttributes(actions[0].Context.Attributes)

	for i := 1; i < len(actions); i++ {
		intersectAttributes(intersection, actions[i].Context.Attributes)
	}

	// Return with non-nil Attributes map (empty means "known but no common attributes")
	return schema.RecordType{Attributes: intersection}
}

// copyAttributes creates a copy of an attribute map.
func copyAttributes(attrs map[string]schema.AttributeType) map[string]schema.AttributeType {
	result := make(map[string]schema.AttributeType)
	maps.Copy(result, attrs)
	return result
}

// intersectAttributes modifies intersection to keep only attributes that exist in both maps with matching types.
func intersectAttributes(intersection map[string]schema.AttributeType, other map[string]schema.AttributeType) {
	for name, attr := range intersection {
		otherAttr, ok := other[name]
		if !ok || !schema.TypesMatch(attr.Type, otherAttr.Type) {
			delete(intersection, name)
			continue
		}
		// Keep the stricter "required" setting
		if !otherAttr.Required {
			attr.Required = false
			intersection[name] = attr
		}
	}
}

// mapKeysToSlice extracts keys from a map to a slice.
func mapKeysToSlice(m map[types.EntityType]bool) []types.EntityType {
	result := make([]types.EntityType, 0, len(m))
	for t := range m {
		result = append(result, t)
	}
	return result
}

// resolveEntityScopeTypes resolves entity types from an entity scope.
func (v *Validator) resolveEntityScopeTypes(scope ast.IsScopeNode, actionTypes []types.EntityType) []types.EntityType {
	switch s := scope.(type) {
	case ast.ScopeTypeAll:
		if len(actionTypes) > 0 {
			return actionTypes
		}
		return v.allEntityTypes()
	case ast.ScopeTypeEq:
		return []types.EntityType{s.Entity.Type}
	case ast.ScopeTypeIn:
		return []types.EntityType{s.Entity.Type}
	case ast.ScopeTypeIs:
		return []types.EntityType{s.Type}
	case ast.ScopeTypeIsIn:
		return []types.EntityType{s.Type}
	}
	return nil
}

// extractActionUID returns the specific action UID if the scope is Eq
func (v *Validator) extractActionUID(scope ast.IsActionScopeNode) *types.EntityUID {
	switch s := scope.(type) {
	case ast.ScopeTypeEq:
		return &s.Entity
	}
	return nil
}

// allEntityTypes returns all defined entity types
func (v *Validator) allEntityTypes() []types.EntityType {
	var result []types.EntityType
	for t := range v.entityTypes {
		result = append(result, t)
	}
	return result
}

// typecheck infers the type of an AST node and reports type errors
func (ctx *typeContext) typecheck(node ast.IsNode) schema.CedarType {
	if node == nil {
		return schema.UnknownType{}
	}

	switch n := node.(type) {
	case ast.NodeValue:
		return ctx.typecheckValue(n.Value)
	case ast.NodeTypeVariable:
		return ctx.typecheckVariable(n)
	case ast.NodeTypeOr, ast.NodeTypeAnd:
		return ctx.typecheckBooleanBinary(n)
	case ast.NodeTypeEquals, ast.NodeTypeNotEquals:
		return ctx.typecheckEquality(n)
	case ast.NodeTypeLessThan, ast.NodeTypeLessThanOrEqual,
		ast.NodeTypeGreaterThan, ast.NodeTypeGreaterThanOrEqual:
		return ctx.typecheckComparison(n)
	case ast.NodeTypeNot:
		return ctx.typecheckUnaryBool(n.Arg, "! operator")
	case ast.NodeTypeNegate:
		return ctx.typecheckUnaryLong(n.Arg, "negation")
	case ast.NodeTypeAdd, ast.NodeTypeSub, ast.NodeTypeMult:
		return ctx.typecheckArithmetic(n)
	case ast.NodeTypeIn:
		return ctx.typecheckIn(n)
	case ast.NodeTypeIs:
		ctx.typecheck(n.Left)
		return schema.BoolType{}
	case ast.NodeTypeIsIn:
		ctx.typecheck(n.Left)
		ctx.typecheck(n.Entity)
		// Check for impossible "is ... in ..." relationships
		ctx.checkImpossibleIsInRelationship(n)
		return schema.BoolType{}
	case ast.NodeTypeAccess:
		return ctx.typecheckAccess(n)
	case ast.NodeTypeHas:
		ctx.typecheck(n.Arg)
		return schema.BoolType{}
	case ast.NodeTypeContains, ast.NodeTypeContainsAll, ast.NodeTypeContainsAny:
		return ctx.typecheckSetOp(n)
	case ast.NodeTypeIsEmpty:
		return ctx.typecheckUnarySet(n.Arg)
	case ast.NodeTypeLike:
		return ctx.typecheckUnaryString(n.Arg)
	case ast.NodeTypeIfThenElse:
		return ctx.typecheckConditional(n)
	case ast.NodeTypeSet:
		return ctx.typecheckSetLiteral(n)
	case ast.NodeTypeRecord:
		return ctx.typecheckRecordLiteral(n)
	case ast.NodeTypeExtensionCall:
		return ctx.typecheckExtensionCall(n)
	case ast.NodeTypeGetTag:
		ctx.typecheck(n.Left)
		ctx.typecheck(n.Right)
		return schema.UnknownType{}
	case ast.NodeTypeHasTag:
		ctx.typecheck(n.Left)
		ctx.typecheck(n.Right)
		return schema.BoolType{}
	default:
		return schema.UnknownType{}
	}
}

// typecheckUnaryBool checks a unary operator that requires a boolean operand.
func (ctx *typeContext) typecheckUnaryBool(arg ast.IsNode, opName string) schema.CedarType {
	argType := ctx.typecheck(arg)
	if !isTypeBoolean(argType) && !isTypeUnknown(argType) {
		ctx.errors = append(ctx.errors, fmt.Sprintf("unexpectedType: %s requires boolean operand, got %s", opName, argType))
	}
	return schema.BoolType{}
}

// typecheckUnaryLong checks a unary operator that requires a Long operand.
func (ctx *typeContext) typecheckUnaryLong(arg ast.IsNode, opName string) schema.CedarType {
	argType := ctx.typecheck(arg)
	if !isTypeLong(argType) && !isTypeUnknown(argType) {
		ctx.errors = append(ctx.errors, fmt.Sprintf("unexpectedType: %s requires Long operand, got %s", opName, argType))
	}
	return schema.LongType{}
}

// typecheckUnarySet checks an operator that requires a Set operand.
func (ctx *typeContext) typecheckUnarySet(arg ast.IsNode) schema.CedarType {
	argType := ctx.typecheck(arg)
	if !isTypeSet(argType) && !isTypeUnknown(argType) {
		ctx.errors = append(ctx.errors, fmt.Sprintf("unexpectedType: isEmpty() requires Set operand, got %s", argType))
	}
	return schema.BoolType{}
}

// typecheckUnaryString checks the like operator that requires a String operand.
func (ctx *typeContext) typecheckUnaryString(arg ast.IsNode) schema.CedarType {
	argType := ctx.typecheck(arg)
	if !isTypeString(argType) && !isTypeUnknown(argType) {
		ctx.errors = append(ctx.errors, fmt.Sprintf("unexpectedType: like operator requires String operand, got %s", argType))
	}
	return schema.BoolType{}
}

// typecheckConditional handles if-then-else expressions.
func (ctx *typeContext) typecheckConditional(n ast.NodeTypeIfThenElse) schema.CedarType {
	condType := ctx.typecheck(n.If)
	if !isTypeBoolean(condType) && !isTypeUnknown(condType) {
		ctx.errors = append(ctx.errors, fmt.Sprintf("unexpectedType: if condition must be boolean, got %s", condType))
	}
	thenType := ctx.typecheck(n.Then)
	elseType := ctx.typecheck(n.Else)
	unified := unifyTypes(thenType, elseType)
	// Check if unification failed - report lubErr
	if _, isUnknown := unified.(schema.UnknownType); isUnknown {
		if !isTypeUnknown(thenType) && !isTypeUnknown(elseType) {
			ctx.errors = append(ctx.errors,
				fmt.Sprintf("lubErr: if-then-else branches have incompatible types: %s and %s", thenType, elseType))
		}
	}
	return unified
}

// typecheckSetLiteral handles set literal expressions.
func (ctx *typeContext) typecheckSetLiteral(n ast.NodeTypeSet) schema.CedarType {
	if len(n.Elements) == 0 {
		// Empty set literals are a type error in Lean (emptySetErr)
		// because the element type cannot be inferred.
		ctx.errors = append(ctx.errors, "emptySetErr: cannot infer element type of empty set literal")
		return schema.SetType{Element: schema.UnknownType{}}
	}
	var elemType schema.CedarType = schema.UnknownType{}
	var incompatibleTypes []schema.CedarType
	for _, elem := range n.Elements {
		t := ctx.typecheck(elem)
		unified := unifyTypes(elemType, t)
		// Check if unification failed (resulted in UnknownType when both inputs were known)
		if _, isUnknown := unified.(schema.UnknownType); isUnknown {
			if !isTypeUnknown(elemType) && !isTypeUnknown(t) {
				// Types are incompatible - collect them for error reporting
				incompatibleTypes = append(incompatibleTypes, t)
			}
		}
		elemType = unified
	}
	// Report incompatible set types if any were found
	if len(incompatibleTypes) > 0 {
		ctx.errors = append(ctx.errors, "incompatibleSetTypes: set elements have incompatible types")
	}
	return schema.SetType{Element: elemType}
}

// typecheckRecordLiteral handles record literal expressions.
func (ctx *typeContext) typecheckRecordLiteral(n ast.NodeTypeRecord) schema.CedarType {
	attrs := make(map[string]schema.AttributeType)
	for _, elem := range n.Elements {
		t := ctx.typecheck(elem.Value)
		attrs[string(elem.Key)] = schema.AttributeType{Type: t, Required: true}
	}
	return schema.RecordType{Attributes: attrs}
}

// typecheckValue handles literal values and checks for unknown entity types.
func (ctx *typeContext) typecheckValue(val types.Value) schema.CedarType {
	if euid, ok := val.(types.EntityUID); ok {
		ctx.checkEntityTypeKnown(euid)
	}
	return ctx.v.inferType(val)
}

// checkEntityTypeKnown verifies that an entity literal references a known type.
func (ctx *typeContext) checkEntityTypeKnown(euid types.EntityUID) {
	if _, exists := ctx.v.entityTypes[euid.Type]; exists {
		return // Type is known
	}

	if ctx.v.isActionEntityType(euid.Type) {
		// For action entity types, the specific entity must be a defined action
		if !ctx.v.isKnownActionEntity(euid) {
			ctx.errors = append(ctx.errors, fmt.Sprintf("unknownEntity: entity %s is not defined in schema", euid))
		}
		return
	}

	// Not in entityTypes and not an action type - unknown entity
	ctx.errors = append(ctx.errors, fmt.Sprintf("unknownEntity: entity type %s is not defined in schema", euid.Type))
}

// typecheckVariable handles variable references (principal, action, resource, context)
func (ctx *typeContext) typecheckVariable(n ast.NodeTypeVariable) schema.CedarType {
	switch string(n.Name) {
	case "principal":
		if len(ctx.principalTypes) == 1 {
			return schema.EntityCedarType{Name: ctx.principalTypes[0]}
		}
		return schema.EntityCedarType{} // Unknown entity type
	case "action":
		if ctx.actionUID != nil {
			return schema.EntityCedarType{Name: ctx.actionUID.Type}
		}
		return schema.EntityCedarType{Name: "Action"}
	case "resource":
		if len(ctx.resourceTypes) == 1 {
			return schema.EntityCedarType{Name: ctx.resourceTypes[0]}
		}
		return schema.EntityCedarType{}
	case "context":
		// Use the pre-computed context type from effective actions
		return ctx.contextType
	default:
		return schema.UnknownType{}
	}
}

// typecheckBooleanBinary handles && and || operators
func (ctx *typeContext) typecheckBooleanBinary(node ast.IsNode) schema.CedarType {
	var left, right ast.IsNode
	switch n := node.(type) {
	case ast.NodeTypeOr:
		left, right = n.Left, n.Right
	case ast.NodeTypeAnd:
		left, right = n.Left, n.Right
	}

	leftType := ctx.typecheck(left)
	rightType := ctx.typecheck(right)

	if !isTypeBoolean(leftType) && !isTypeUnknown(leftType) {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("unexpectedType: boolean operator requires boolean operands, got %s", leftType))
	}
	if !isTypeBoolean(rightType) && !isTypeUnknown(rightType) {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("unexpectedType: boolean operator requires boolean operands, got %s", rightType))
	}
	return schema.BoolType{}
}

// typecheckEquality handles == and != operators
func (ctx *typeContext) typecheckEquality(node ast.IsNode) schema.CedarType {
	var left, right ast.IsNode
	switch n := node.(type) {
	case ast.NodeTypeEquals:
		left, right = n.Left, n.Right
	case ast.NodeTypeNotEquals:
		left, right = n.Left, n.Right
	}

	leftType := ctx.typecheck(left)
	rightType := ctx.typecheck(right)

	// Cedar requires that equality operands have compatible types.
	// This is a type error, not a runtime behavior (which would return false).
	// Note: typesAreComparable handles unknown types by allowing comparisons,
	// matching Lean's lenient behavior with unresolved types.
	if !isTypeUnknown(leftType) && !isTypeUnknown(rightType) {
		if !ctx.typesAreComparable(leftType, rightType) {
			ctx.errors = append(ctx.errors,
				fmt.Sprintf("lubErr: type mismatch in equality: cannot compare %s with %s", leftType, rightType))
		}
	}

	// Check for impossible equality between principal and resource.
	// When comparing principal == resource (or resource == principal),
	// if their type sets are completely disjoint, the comparison can never be true,
	// making the policy impossible. This matches Lean's impossiblePolicy check.
	ctx.checkPrincipalResourceEquality(left, right)

	return schema.BoolType{}
}

// checkPrincipalResourceEquality detects impossible equality between principal and resource.
// When principal and resource have disjoint type sets, comparing them for equality
// will always be false, making any policy with such a condition impossible.
func (ctx *typeContext) checkPrincipalResourceEquality(left, right ast.IsNode) {
	if !ctx.isPrincipalResourceComparison(left, right) {
		return
	}

	if len(ctx.principalTypes) == 0 || len(ctx.resourceTypes) == 0 {
		return // Can't determine impossibility with empty type sets
	}

	if !ctx.typeSetsOverlap(ctx.principalTypes, ctx.resourceTypes) {
		ctx.errors = append(ctx.errors,
			"impossiblePolicy: principal and resource have disjoint types, equality can never be true")
	}
}

// isPrincipalResourceComparison checks if left and right represent principal == resource or vice versa.
func (ctx *typeContext) isPrincipalResourceComparison(left, right ast.IsNode) bool {
	leftVar, leftIsVar := left.(ast.NodeTypeVariable)
	rightVar, rightIsVar := right.(ast.NodeTypeVariable)
	if !leftIsVar || !rightIsVar {
		return false
	}

	leftName, rightName := string(leftVar.Name), string(rightVar.Name)
	return (leftName == "principal" && rightName == "resource") ||
		(leftName == "resource" && rightName == "principal")
}

// typeSetsOverlap checks if two entity type slices have any common element.
func (ctx *typeContext) typeSetsOverlap(a, b []types.EntityType) bool {
	for _, pt := range a {
		if slices.Contains(b, pt) {
			return true
		}
	}
	return false
}

// typecheckComparison handles <, <=, >, >= operators
func (ctx *typeContext) typecheckComparison(node ast.IsNode) schema.CedarType {
	var left, right ast.IsNode
	switch n := node.(type) {
	case ast.NodeTypeLessThan:
		left, right = n.Left, n.Right
	case ast.NodeTypeLessThanOrEqual:
		left, right = n.Left, n.Right
	case ast.NodeTypeGreaterThan:
		left, right = n.Left, n.Right
	case ast.NodeTypeGreaterThanOrEqual:
		left, right = n.Left, n.Right
	}

	leftType := ctx.typecheck(left)
	rightType := ctx.typecheck(right)

	if !isTypeLong(leftType) && !isTypeUnknown(leftType) {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("unexpectedType: comparison operator requires Long operands, got %s", leftType))
	}
	if !isTypeLong(rightType) && !isTypeUnknown(rightType) {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("unexpectedType: comparison operator requires Long operands, got %s", rightType))
	}
	return schema.BoolType{}
}

// typecheckArithmetic handles +, -, * operators
func (ctx *typeContext) typecheckArithmetic(node ast.IsNode) schema.CedarType {
	var left, right ast.IsNode
	switch n := node.(type) {
	case ast.NodeTypeAdd:
		left, right = n.Left, n.Right
	case ast.NodeTypeSub:
		left, right = n.Left, n.Right
	case ast.NodeTypeMult:
		left, right = n.Left, n.Right
	}

	leftType := ctx.typecheck(left)
	rightType := ctx.typecheck(right)

	if !isTypeLong(leftType) && !isTypeUnknown(leftType) {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("unexpectedType: arithmetic operator requires Long operands, got %s", leftType))
	}
	if !isTypeLong(rightType) && !isTypeUnknown(rightType) {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("unexpectedType: arithmetic operator requires Long operands, got %s", rightType))
	}
	return schema.LongType{}
}

// typecheckIn handles the 'in' operator
func (ctx *typeContext) typecheckIn(n ast.NodeTypeIn) schema.CedarType {
	leftType := ctx.typecheck(n.Left)
	rightType := ctx.typecheck(n.Right)

	// Left must be an entity or set of entities
	if !isTypeEntity(leftType) && !isTypeUnknown(leftType) {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("unexpectedType: 'in' operator left operand must be entity, got %s", leftType))
	}

	// Right must be an entity or set of entities
	if !isTypeEntity(rightType) && !isTypeSet(rightType) && !isTypeUnknown(rightType) {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("unexpectedType: 'in' operator right operand must be entity or set, got %s", rightType))
	}

	// Check for impossible "in" relationships in conditions.
	// When the left operand is principal or resource, and the right operand is
	// an entity literal, we can check if the "in" relationship is satisfiable
	// based on memberOfTypes relationships.
	ctx.checkImpossibleInRelationship(n.Left, n.Right)

	return schema.BoolType{}
}

// checkImpossibleInRelationship detects when an "in" relationship is impossible.
// For example, "principal in Type3::X" is impossible if principal's type has no
// memberOfTypes chain that includes Type3.
func (ctx *typeContext) checkImpossibleInRelationship(left, right ast.IsNode) {
	possibleTypes, varName := ctx.getPossibleTypesForVariable(left)
	if len(possibleTypes) == 0 {
		return
	}

	targetType := ctx.extractEntityTypeFromNode(right)
	if targetType == "" {
		return
	}

	if !ctx.canAnyTypeReachTarget(possibleTypes, targetType) {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("impossiblePolicy: %s in %s can never be true (no type in %v has memberOfTypes containing %s)",
				varName, targetType, possibleTypes, targetType))
	}
}

// getPossibleTypesForVariable returns the possible entity types for a variable node.
func (ctx *typeContext) getPossibleTypesForVariable(node ast.IsNode) ([]types.EntityType, string) {
	varNode, ok := node.(ast.NodeTypeVariable)
	if !ok {
		return nil, ""
	}

	switch string(varNode.Name) {
	case "principal":
		return ctx.principalTypes, "principal"
	case "resource":
		return ctx.resourceTypes, "resource"
	default:
		return nil, ""
	}
}

// canAnyTypeReachTarget checks if any type in the list can reach the target type.
func (ctx *typeContext) canAnyTypeReachTarget(possibleTypes []types.EntityType, targetType types.EntityType) bool {
	for _, pt := range possibleTypes {
		// An entity is always "in" itself (reflexive)
		if pt == targetType {
			return true
		}
		if ctx.v.canBeDescendantOf(pt, targetType, make(map[types.EntityType]bool)) {
			return true
		}
	}
	return false
}

// extractEntityTypeFromNode extracts the entity type from a node if it's an entity literal.
func (ctx *typeContext) extractEntityTypeFromNode(node ast.IsNode) types.EntityType {
	switch n := node.(type) {
	case ast.NodeValue:
		if euid, ok := n.Value.(types.EntityUID); ok {
			return euid.Type
		}
	case ast.NodeTypeSet:
		// For a set of entities, extract type from first element
		if len(n.Elements) > 0 {
			return ctx.extractEntityTypeFromNode(n.Elements[0])
		}
	}
	return ""
}

// checkImpossibleIsInRelationship detects when an "is T in E" relationship is impossible.
// For example, "principal is Type3 in Type2::X" is impossible if Type3 has no
// memberOfTypes chain that includes Type2.
func (ctx *typeContext) checkImpossibleIsInRelationship(n ast.NodeTypeIsIn) {
	// The "is T" part constrains the type to exactly T (from embedded NodeTypeIs)
	isType := n.EntityType

	// Get the target entity type from the "in E" part
	targetType := ctx.extractEntityTypeFromNode(n.Entity)
	if targetType == "" {
		return // Can't determine target type
	}

	// Check if the "is" type can be a descendant of the target type
	// An entity is always "in" itself (reflexive), so if types match, it's satisfiable
	if isType == targetType {
		return // Satisfiable
	}

	// Check if isType can be a descendant of targetType via memberOfTypes
	if ctx.v.canBeDescendantOf(isType, targetType, make(map[types.EntityType]bool)) {
		return // Satisfiable
	}

	// Determine variable name for error message
	varName := "entity"
	if varNode, ok := n.Left.(ast.NodeTypeVariable); ok {
		varName = string(varNode.Name)
	}
	ctx.errors = append(ctx.errors,
		fmt.Sprintf("impossiblePolicy: %s is %s in %s can never be true (%s has no memberOfTypes containing %s)",
			varName, isType, targetType, isType, targetType))
}

// typecheckAccess handles attribute access (e.g., principal.name)
func (ctx *typeContext) typecheckAccess(n ast.NodeTypeAccess) schema.CedarType {
	ctx.currentLevel++
	defer func() { ctx.currentLevel-- }()

	if ctx.v.maxAttributeLevel > 0 && ctx.currentLevel > ctx.v.maxAttributeLevel {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("levelError: attribute access exceeds maximum level %d (current level: %d)",
				ctx.v.maxAttributeLevel, ctx.currentLevel))
	}

	baseType := ctx.typecheckWithoutLevelIncrement(n.Arg)
	attrName := string(n.Value)

	switch t := baseType.(type) {
	case schema.EntityCedarType:
		return ctx.typecheckEntityAttrAccess(t, attrName)
	case schema.RecordType:
		return ctx.typecheckRecordAttrAccess(t, attrName)
	case schema.UnknownType:
		return schema.UnknownType{}
	default:
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("unexpectedType: cannot access attribute '%s' on type %s", attrName, baseType))
		return schema.UnknownType{}
	}
}

// typecheckEntityAttrAccess handles attribute access on entity types.
func (ctx *typeContext) typecheckEntityAttrAccess(t schema.EntityCedarType, attrName string) schema.CedarType {
	info, ok := ctx.v.entityTypes[t.Name]
	if !ok {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("unknownEntity: cannot access attribute '%s' on unknown entity type %s", attrName, t.Name))
		return schema.UnknownType{}
	}

	attr, ok := info.Attributes[attrName]
	if !ok {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("attrNotFound: entity type %s does not have attribute '%s'", t.Name, attrName))
		return schema.UnknownType{}
	}

	if !attr.Required {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("attrNotFound: attribute '%s' on entity type %s is optional; use `has` to check for its presence first", attrName, t.Name))
	}
	return attr.Type
}

// typecheckRecordAttrAccess handles attribute access on record types.
func (ctx *typeContext) typecheckRecordAttrAccess(t schema.RecordType, attrName string) schema.CedarType {
	attr, ok := t.Attributes[attrName]
	if !ok {
		// If we have a known record type (Attributes is not nil), accessing a
		// non-existent attribute is an error. This happens when context.attr
		// is accessed but the attribute doesn't exist in all effective actions' contexts.
		if t.Attributes != nil {
			ctx.errors = append(ctx.errors,
				fmt.Sprintf("attrNotFound: attribute '%s' not found in record type", attrName))
		}
		return schema.UnknownType{}
	}

	if !attr.Required {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("attrNotFound: attribute '%s' is optional; use `has` to check for its presence first", attrName))
	}
	return attr.Type
}

// typecheckWithoutLevelIncrement is used for nested access to avoid double counting
func (ctx *typeContext) typecheckWithoutLevelIncrement(node ast.IsNode) schema.CedarType {
	if node == nil {
		return schema.UnknownType{}
	}

	// For nested access nodes, delegate to typecheckAccess which handles its own level
	if n, ok := node.(ast.NodeTypeAccess); ok {
		return ctx.typecheckAccess(n)
	}

	// For all other nodes, use regular typecheck
	return ctx.typecheck(node)
}

// typecheckSetOp handles contains, containsAll, containsAny
func (ctx *typeContext) typecheckSetOp(node ast.IsNode) schema.CedarType {
	var left, right ast.IsNode
	switch n := node.(type) {
	case ast.NodeTypeContains:
		left, right = n.Left, n.Right
	case ast.NodeTypeContainsAll:
		left, right = n.Left, n.Right
	case ast.NodeTypeContainsAny:
		left, right = n.Left, n.Right
	}

	leftType := ctx.typecheck(left)
	rightType := ctx.typecheck(right)

	if !isTypeSet(leftType) && !isTypeUnknown(leftType) {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("unexpectedType: set operation requires Set operand, got %s", leftType))
	}

	_ = rightType // Right operand type depends on the specific operation
	return schema.BoolType{}
}

// typecheckExtensionCall handles extension function calls
func (ctx *typeContext) typecheckExtensionCall(n ast.NodeTypeExtensionCall) schema.CedarType {
	// Type-check all arguments and collect their types
	argTypes := make([]schema.CedarType, len(n.Args))
	for i, arg := range n.Args {
		argTypes[i] = ctx.typecheck(arg)
	}

	funcName := string(n.Name)

	// Validate argument types and determine return type based on function name
	switch funcName {
	// IP address constructor: ip(String) -> ipaddr
	case "ip", "ipaddr":
		ctx.expectArgs(funcName, argTypes, schema.StringType{})
		// Validate IP address literal if argument is a literal string
		ctx.validateExtensionLiteral(n.Args, "ip", isValidIPLiteral)
		return schema.ExtensionType{Name: "ipaddr"}

	// IP address methods (called on ipaddr, no additional args)
	case "isIpv4", "isIpv6", "isLoopback", "isMulticast":
		ctx.expectArgs(funcName, argTypes, schema.ExtensionType{Name: "ipaddr"})
		return schema.BoolType{}

	// isInRange: ipaddr.isInRange(ipaddr) -> Bool
	case "isInRange":
		ctx.expectArgs(funcName, argTypes, schema.ExtensionType{Name: "ipaddr"}, schema.ExtensionType{Name: "ipaddr"})
		return schema.BoolType{}

	// Decimal constructor: decimal(String) -> decimal
	case "decimal":
		ctx.expectArgs(funcName, argTypes, schema.StringType{})
		ctx.validateExtensionLiteral(n.Args, "decimal", isValidDecimalLiteral)
		return schema.ExtensionType{Name: "decimal"}

	// Decimal comparison methods: decimal.lessThan(decimal) -> Bool
	case "lessThan", "lessThanOrEqual", "greaterThan", "greaterThanOrEqual":
		ctx.expectArgs(funcName, argTypes, schema.ExtensionType{Name: "decimal"}, schema.ExtensionType{Name: "decimal"})
		return schema.BoolType{}

	// Datetime constructor: datetime(String) -> datetime
	case "datetime":
		ctx.expectArgs(funcName, argTypes, schema.StringType{})
		ctx.validateExtensionLiteral(n.Args, "datetime", isValidDatetimeLiteral)
		return schema.ExtensionType{Name: "datetime"}

	// Duration constructor: duration(String) -> duration
	case "duration":
		ctx.expectArgs(funcName, argTypes, schema.StringType{})
		ctx.validateExtensionLiteral(n.Args, "duration", isValidDurationLiteral)
		return schema.ExtensionType{Name: "duration"}

	// Datetime arithmetic: datetime.offset(duration) -> datetime
	case "offset":
		ctx.expectArgs(funcName, argTypes, schema.ExtensionType{Name: "datetime"}, schema.ExtensionType{Name: "duration"})
		return schema.ExtensionType{Name: "datetime"}

	// Datetime difference: datetime.durationSince(datetime) -> duration
	case "durationSince":
		ctx.expectArgs(funcName, argTypes, schema.ExtensionType{Name: "datetime"}, schema.ExtensionType{Name: "datetime"})
		return schema.ExtensionType{Name: "duration"}

	// Datetime extraction methods (called on datetime, no additional args)
	case "toDate", "toTime":
		ctx.expectArgs(funcName, argTypes, schema.ExtensionType{Name: "datetime"})
		return schema.ExtensionType{Name: "datetime"}

	// Duration conversion methods (called on duration, no additional args)
	case "toDays", "toHours", "toMinutes", "toSeconds", "toMilliseconds":
		ctx.expectArgs(funcName, argTypes, schema.ExtensionType{Name: "duration"})
		return schema.LongType{}

	default:
		return schema.UnknownType{}
	}
}

// expectArgs validates that the provided argument types match the expected types.
// If there's a mismatch, it reports a type error.
func (ctx *typeContext) expectArgs(funcName string, actual []schema.CedarType, expected ...schema.CedarType) {
	if len(actual) != len(expected) {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("extensionErr: %s() expects %d argument(s), got %d", funcName, len(expected), len(actual)))
		return
	}

	for i, exp := range expected {
		act := actual[i]
		if !isTypeUnknown(act) && !schema.TypesMatch(exp, act) {
			ctx.errors = append(ctx.errors,
				fmt.Sprintf("extensionErr: %s() argument %d: expected %s, got %s", funcName, i+1, exp, act))
		}
	}
}

// validateExtensionLiteral validates extension constructor literals.
// If the first argument is a literal string, it checks if it's valid using the validator function.
func (ctx *typeContext) validateExtensionLiteral(args []ast.IsNode, funcName string, isValid func(string) bool) {
	if len(args) == 0 {
		return
	}
	// Check if the argument is a literal string value
	if nodeVal, ok := args[0].(ast.NodeValue); ok {
		if str, ok := nodeVal.Value.(types.String); ok {
			if !isValid(string(str)) {
				ctx.errors = append(ctx.errors,
					fmt.Sprintf("extensionErr: invalid %s literal: %q", funcName, string(str)))
			}
		}
	}
}

// isValidIPLiteral checks if a string is a valid IP address or CIDR notation.
func isValidIPLiteral(s string) bool {
	if s == "" {
		return false
	}
	// Try parsing as IP address
	if _, err := types.ParseIPAddr(s); err == nil {
		return true
	}
	return false
}

// isValidDecimalLiteral checks if a string is a valid decimal literal.
func isValidDecimalLiteral(s string) bool {
	if s == "" {
		return false
	}
	// Try parsing as decimal
	if _, err := types.ParseDecimal(s); err == nil {
		return true
	}
	return false
}

// isValidDatetimeLiteral checks if a string is a valid datetime literal.
func isValidDatetimeLiteral(s string) bool {
	if s == "" {
		return false
	}
	// Try parsing as datetime
	if _, err := types.ParseDatetime(s); err == nil {
		return true
	}
	return false
}

// isValidDurationLiteral checks if a string is a valid duration literal.
func isValidDurationLiteral(s string) bool {
	if s == "" {
		return false
	}
	// Try parsing as duration
	if _, err := types.ParseDuration(s); err == nil {
		return true
	}
	return false
}

// ============================================================================
// Type Checking Helpers
// ============================================================================

// isTypeBoolean returns true if the type is BoolType.
func isTypeBoolean(t schema.CedarType) bool {
	_, ok := t.(schema.BoolType)
	return ok
}

// isTypeLong returns true if the type is LongType.
func isTypeLong(t schema.CedarType) bool {
	_, ok := t.(schema.LongType)
	return ok
}

// isTypeString returns true if the type is StringType.
func isTypeString(t schema.CedarType) bool {
	_, ok := t.(schema.StringType)
	return ok
}

// isTypeEntity returns true if the type is EntityCedarType.
func isTypeEntity(t schema.CedarType) bool {
	_, ok := t.(schema.EntityCedarType)
	return ok
}

// isTypeSet returns true if the type is SetType.
func isTypeSet(t schema.CedarType) bool {
	_, ok := t.(schema.SetType)
	return ok
}

// isTypeUnknown returns true if the type is UnknownType.
func isTypeUnknown(t schema.CedarType) bool {
	_, ok := t.(schema.UnknownType)
	return ok
}

// unifyTypes returns a type that represents both types.
// If either type is unknown, returns the other.
// If types match, returns the first.
// Otherwise returns UnknownType.
func unifyTypes(t1, t2 schema.CedarType) schema.CedarType {
	if isTypeUnknown(t1) {
		return t2
	}
	if isTypeUnknown(t2) {
		return t1
	}
	if schema.TypesMatch(t1, t2) {
		return t1
	}
	return schema.UnknownType{}
}

// typeCat represents a type category for comparison purposes.
// Types in the same category can be compared with == and !=.
type typeCat int

const (
	catUnknown typeCat = iota
	catBool
	catLong
	catString
	catEntity
	catSet
	catRecord
	catExtDecimal
	catExtIPAddr
	catExtDatetime
	catExtDuration
)

// typesAreComparable checks if two types can be compared with == or !=.
// Cedar's type system requires that equality operands have the same base type.
// However, if either type is unknown or unresolved, we allow the comparison
// to match Lean's lenient behavior.
func (ctx *typeContext) typesAreComparable(t1, t2 schema.CedarType) bool {
	cat1 := ctx.typeCategory(t1)
	cat2 := ctx.typeCategory(t2)

	// If either type is unknown, comparisons are allowed (lenient)
	if cat1 == catUnknown || cat2 == catUnknown {
		return true
	}

	// Types must be in the same category to be comparable
	if cat1 != cat2 {
		return false
	}

	// For record types, we need additional checks for lub compatibility.
	// Two records can only be compared if they have a valid least upper bound (lub).
	// This requires that for closed records, neither has attributes the other lacks.
	if cat1 == catRecord {
		r1, ok1 := t1.(schema.RecordType)
		r2, ok2 := t2.(schema.RecordType)
		if ok1 && ok2 {
			return ctx.recordTypesHaveLub(r1, r2)
		}
	}

	return true
}

// recordTypesHaveLub checks if two record types have a valid least upper bound.
// For records to have a lub:
// 1. Common attributes must have compatible types
// 2. For closed records, attributes in one that don't exist in the other cause a lubErr
func (ctx *typeContext) recordTypesHaveLub(r1, r2 schema.RecordType) bool {
	// Check all attributes in r1
	for name, attr1 := range r1.Attributes {
		if attr2, exists := r2.Attributes[name]; exists {
			// Common attribute - check types are compatible
			if !ctx.typesAreComparable(attr1.Type, attr2.Type) {
				return false
			}
		} else {
			// Attribute in r1 but not in r2
			// If r2 is closed (not open), this is a lubErr
			if !r2.OpenRecord {
				return false
			}
		}
	}

	// Check attributes in r2 that aren't in r1
	for name := range r2.Attributes {
		if _, exists := r1.Attributes[name]; !exists {
			// Attribute in r2 but not in r1
			// If r1 is closed (not open), this is a lubErr
			if !r1.OpenRecord {
				return false
			}
		}
	}

	return true
}

// typeCategory returns the category of a type for comparison purposes.
func (ctx *typeContext) typeCategory(t schema.CedarType) typeCat {
	switch ct := t.(type) {
	case schema.BoolType:
		return catBool
	case schema.LongType:
		return catLong
	case schema.StringType:
		return catString
	case schema.EntityCedarType:
		// All entity types are in the entity category, regardless of whether
		// they're defined in entityTypes. This includes:
		// - Action entity types (in actionTypes)
		// - Empty entity type (used for variables with unknown specific type)
		// - Entity types from action's principalTypes/resourceTypes
		// - Entity types from attributes
		// This ensures comparing entities with non-entities (like strings) is an error.
		return catEntity
	case schema.AnyEntityType:
		return catEntity
	case schema.SetType:
		return catSet
	case schema.RecordType:
		return catRecord
	case schema.ExtensionType:
		switch ct.Name {
		case "decimal":
			return catExtDecimal
		case "ipaddr":
			return catExtIPAddr
		case "datetime":
			return catExtDatetime
		case "duration":
			return catExtDuration
		}
		return catUnknown
	case schema.UnspecifiedType:
		// UnspecifiedType is treated as unknown for comparison purposes.
		// This allows comparisons with unspecified types (they return Bool),
		// while using unspecified types as conditions is caught separately.
		return catUnknown
	default:
		return catUnknown
	}
}
