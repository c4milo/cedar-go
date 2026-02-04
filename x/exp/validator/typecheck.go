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

	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
)

// typeContext holds the type environment during type-checking
type typeContext struct {
	v              *Validator
	principalTypes []types.EntityType // Possible types for principal
	resourceTypes  []types.EntityType // Possible types for resource
	actionUID      *types.EntityUID   // Specific action (if known)
	errors         []string
	currentLevel   int // Current attribute dereference level
}

// typecheckPolicy performs full type-checking on a policy
func (v *Validator) typecheckPolicy(p *ast.Policy) []string {
	ctx := &typeContext{
		v: v,
	}

	// Determine the types of principal, action, and resource from scope
	ctx.principalTypes = v.extractPrincipalTypes(p.Principal, p.Action)
	ctx.resourceTypes = v.extractResourceTypes(p.Resource, p.Action)
	ctx.actionUID = v.extractActionUID(p.Action)

	// Type-check each condition
	for _, cond := range p.Conditions {
		inferredType := ctx.typecheck(cond.Body)

		// Condition must evaluate to Boolean.
		// We allow UnknownType here for cases where the type can't be determined
		// (e.g., action scope is 'all' so context type is unknown).
		// However, UnspecifiedType (attribute with no type in schema) is NOT allowed
		// as a condition - this is a schema error that should be reported.
		if _, isUnspecified := inferredType.(UnspecifiedType); isUnspecified {
			ctx.errors = append(ctx.errors,
				"condition uses value with unspecified type from schema")
		} else if !isTypeBoolean(inferredType) && !isTypeUnknown(inferredType) {
			ctx.errors = append(ctx.errors,
				fmt.Sprintf("condition must be boolean, got %s", inferredType))
		}
	}

	return ctx.errors
}

// extractPrincipalTypes determines possible principal types from scope
func (v *Validator) extractPrincipalTypes(scope ast.IsPrincipalScopeNode, actionScope ast.IsActionScopeNode) []types.EntityType {
	actionTypes := v.getActionPrincipalTypes(actionScope)
	return v.resolveEntityScopeTypes(scope, actionTypes)
}

// extractResourceTypes determines possible resource types from scope
func (v *Validator) extractResourceTypes(scope ast.IsResourceScopeNode, actionScope ast.IsActionScopeNode) []types.EntityType {
	actionTypes := v.getActionResourceTypes(actionScope)
	return v.resolveEntityScopeTypes(scope, actionTypes)
}

// getActionPrincipalTypes extracts principal types from action scope.
func (v *Validator) getActionPrincipalTypes(actionScope ast.IsActionScopeNode) []types.EntityType {
	switch a := actionScope.(type) {
	case ast.ScopeTypeAll:
		// For unscoped action (all actions), return union of all action's principal types.
		// This enables type checking even when no specific action is constrained.
		return v.allActionPrincipalTypes()
	case ast.ScopeTypeEq:
		if info, ok := v.actionTypes[a.Entity]; ok {
			return info.PrincipalTypes
		}
	case ast.ScopeTypeInSet:
		return v.unionActionPrincipalTypes(a.Entities)
	}
	return nil
}

// getActionResourceTypes extracts resource types from action scope.
func (v *Validator) getActionResourceTypes(actionScope ast.IsActionScopeNode) []types.EntityType {
	switch a := actionScope.(type) {
	case ast.ScopeTypeAll:
		// For unscoped action (all actions), return union of all action's resource types.
		// This enables type checking even when no specific action is constrained.
		return v.allActionResourceTypes()
	case ast.ScopeTypeEq:
		if info, ok := v.actionTypes[a.Entity]; ok {
			return info.ResourceTypes
		}
	case ast.ScopeTypeInSet:
		return v.unionActionResourceTypes(a.Entities)
	}
	return nil
}

// unionActionPrincipalTypes returns the union of principal types from multiple actions.
func (v *Validator) unionActionPrincipalTypes(actionUIDs []types.EntityUID) []types.EntityType {
	typeSet := make(map[types.EntityType]bool)
	for _, actionUID := range actionUIDs {
		if info, ok := v.actionTypes[actionUID]; ok {
			for _, pt := range info.PrincipalTypes {
				typeSet[pt] = true
			}
		}
	}
	return mapKeysToSlice(typeSet)
}

// unionActionResourceTypes returns the union of resource types from multiple actions.
func (v *Validator) unionActionResourceTypes(actionUIDs []types.EntityUID) []types.EntityType {
	typeSet := make(map[types.EntityType]bool)
	for _, actionUID := range actionUIDs {
		if info, ok := v.actionTypes[actionUID]; ok {
			for _, rt := range info.ResourceTypes {
				typeSet[rt] = true
			}
		}
	}
	return mapKeysToSlice(typeSet)
}

// allActionPrincipalTypes returns the union of principal types from all actions.
func (v *Validator) allActionPrincipalTypes() []types.EntityType {
	typeSet := make(map[types.EntityType]bool)
	for _, info := range v.actionTypes {
		for _, pt := range info.PrincipalTypes {
			typeSet[pt] = true
		}
	}
	return mapKeysToSlice(typeSet)
}

// allActionResourceTypes returns the union of resource types from all actions.
func (v *Validator) allActionResourceTypes() []types.EntityType {
	typeSet := make(map[types.EntityType]bool)
	for _, info := range v.actionTypes {
		for _, rt := range info.ResourceTypes {
			typeSet[rt] = true
		}
	}
	return mapKeysToSlice(typeSet)
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
func (ctx *typeContext) typecheck(node ast.IsNode) CedarType {
	if node == nil {
		return UnknownType{}
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
		return BoolType{}
	case ast.NodeTypeIsIn:
		ctx.typecheck(n.Left)
		ctx.typecheck(n.Entity)
		return BoolType{}
	case ast.NodeTypeAccess:
		return ctx.typecheckAccess(n)
	case ast.NodeTypeHas:
		ctx.typecheck(n.Arg)
		return BoolType{}
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
		return UnknownType{}
	case ast.NodeTypeHasTag:
		ctx.typecheck(n.Left)
		ctx.typecheck(n.Right)
		return BoolType{}
	default:
		return UnknownType{}
	}
}

// typecheckUnaryBool checks a unary operator that requires a boolean operand.
func (ctx *typeContext) typecheckUnaryBool(arg ast.IsNode, opName string) CedarType {
	argType := ctx.typecheck(arg)
	if !isTypeBoolean(argType) && !isTypeUnknown(argType) {
		ctx.errors = append(ctx.errors, fmt.Sprintf("%s requires boolean operand, got %s", opName, argType))
	}
	return BoolType{}
}

// typecheckUnaryLong checks a unary operator that requires a Long operand.
func (ctx *typeContext) typecheckUnaryLong(arg ast.IsNode, opName string) CedarType {
	argType := ctx.typecheck(arg)
	if !isTypeLong(argType) && !isTypeUnknown(argType) {
		ctx.errors = append(ctx.errors, fmt.Sprintf("%s requires Long operand, got %s", opName, argType))
	}
	return LongType{}
}

// typecheckUnarySet checks an operator that requires a Set operand.
func (ctx *typeContext) typecheckUnarySet(arg ast.IsNode) CedarType {
	argType := ctx.typecheck(arg)
	if !isTypeSet(argType) && !isTypeUnknown(argType) {
		ctx.errors = append(ctx.errors, fmt.Sprintf("isEmpty() requires Set operand, got %s", argType))
	}
	return BoolType{}
}

// typecheckUnaryString checks the like operator that requires a String operand.
func (ctx *typeContext) typecheckUnaryString(arg ast.IsNode) CedarType {
	argType := ctx.typecheck(arg)
	if !isTypeString(argType) && !isTypeUnknown(argType) {
		ctx.errors = append(ctx.errors, fmt.Sprintf("like operator requires String operand, got %s", argType))
	}
	return BoolType{}
}

// typecheckConditional handles if-then-else expressions.
func (ctx *typeContext) typecheckConditional(n ast.NodeTypeIfThenElse) CedarType {
	condType := ctx.typecheck(n.If)
	if !isTypeBoolean(condType) && !isTypeUnknown(condType) {
		ctx.errors = append(ctx.errors, fmt.Sprintf("if condition must be boolean, got %s", condType))
	}
	thenType := ctx.typecheck(n.Then)
	elseType := ctx.typecheck(n.Else)
	return unifyTypes(thenType, elseType)
}

// typecheckSetLiteral handles set literal expressions.
func (ctx *typeContext) typecheckSetLiteral(n ast.NodeTypeSet) CedarType {
	if len(n.Elements) == 0 {
		return SetType{Element: UnknownType{}}
	}
	var elemType CedarType = UnknownType{}
	for _, elem := range n.Elements {
		t := ctx.typecheck(elem)
		elemType = unifyTypes(elemType, t)
	}
	return SetType{Element: elemType}
}

// typecheckRecordLiteral handles record literal expressions.
func (ctx *typeContext) typecheckRecordLiteral(n ast.NodeTypeRecord) CedarType {
	attrs := make(map[string]AttributeType)
	for _, elem := range n.Elements {
		t := ctx.typecheck(elem.Value)
		attrs[string(elem.Key)] = AttributeType{Type: t, Required: true}
	}
	return RecordType{Attributes: attrs}
}

// typecheckValue handles literal values and checks for unknown entity types.
func (ctx *typeContext) typecheckValue(val types.Value) CedarType {
	// Check for entity literals with unknown entity types
	if euid, ok := val.(types.EntityUID); ok {
		// Check if this entity type exists in the schema
		if _, exists := ctx.v.entityTypes[euid.Type]; !exists && !ctx.v.isActionEntityType(euid.Type) {
			ctx.errors = append(ctx.errors, fmt.Sprintf("unknownEntity: entity type %s is not defined in schema", euid.Type))
		}
	}
	return ctx.v.inferType(val)
}

// typecheckVariable handles variable references (principal, action, resource, context)
func (ctx *typeContext) typecheckVariable(n ast.NodeTypeVariable) CedarType {
	switch string(n.Name) {
	case "principal":
		if len(ctx.principalTypes) == 1 {
			return EntityType{Name: ctx.principalTypes[0]}
		}
		return EntityType{} // Unknown entity type
	case "action":
		if ctx.actionUID != nil {
			return EntityType{Name: ctx.actionUID.Type}
		}
		return EntityType{Name: "Action"}
	case "resource":
		if len(ctx.resourceTypes) == 1 {
			return EntityType{Name: ctx.resourceTypes[0]}
		}
		return EntityType{}
	case "context":
		if ctx.actionUID != nil {
			if info, ok := ctx.v.actionTypes[*ctx.actionUID]; ok {
				return info.Context
			}
		}
		return RecordType{}
	default:
		return UnknownType{}
	}
}

// typecheckBooleanBinary handles && and || operators
func (ctx *typeContext) typecheckBooleanBinary(node ast.IsNode) CedarType {
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
			fmt.Sprintf("boolean operator requires boolean operands, got %s", leftType))
	}
	if !isTypeBoolean(rightType) && !isTypeUnknown(rightType) {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("boolean operator requires boolean operands, got %s", rightType))
	}
	return BoolType{}
}

// typecheckEquality handles == and != operators
func (ctx *typeContext) typecheckEquality(node ast.IsNode) CedarType {
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
				fmt.Sprintf("type mismatch in equality: cannot compare %s with %s", leftType, rightType))
		}
	}

	// Check for impossible equality between principal and resource.
	// When comparing principal == resource (or resource == principal),
	// if their type sets are completely disjoint, the comparison can never be true,
	// making the policy impossible. This matches Lean's impossiblePolicy check.
	ctx.checkPrincipalResourceEquality(left, right)

	return BoolType{}
}

// checkPrincipalResourceEquality detects impossible equality between principal and resource.
// When principal and resource have disjoint type sets, comparing them for equality
// will always be false, making any policy with such a condition impossible.
func (ctx *typeContext) checkPrincipalResourceEquality(left, right ast.IsNode) {
	// Check if this is a principal == resource or resource == principal comparison
	leftVar, leftIsVar := left.(ast.NodeTypeVariable)
	rightVar, rightIsVar := right.(ast.NodeTypeVariable)
	if !leftIsVar || !rightIsVar {
		return
	}

	isPrincipalResource := (string(leftVar.Name) == "principal" && string(rightVar.Name) == "resource") ||
		(string(leftVar.Name) == "resource" && string(rightVar.Name) == "principal")
	if !isPrincipalResource {
		return
	}

	// Check if principal and resource types are disjoint
	if len(ctx.principalTypes) == 0 || len(ctx.resourceTypes) == 0 {
		// If either type set is empty/unknown, we can't determine impossibility
		return
	}

	// Check for any overlap between principal and resource types
	hasOverlap := false
	for _, pt := range ctx.principalTypes {
		if slices.Contains(ctx.resourceTypes, pt) {
			hasOverlap = true
			break
		}
	}

	if !hasOverlap {
		// Types are disjoint - principal and resource can never be equal
		ctx.errors = append(ctx.errors,
			"impossiblePolicy: principal and resource have disjoint types, equality can never be true")
	}
}

// typecheckComparison handles <, <=, >, >= operators
func (ctx *typeContext) typecheckComparison(node ast.IsNode) CedarType {
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
			fmt.Sprintf("comparison operator requires Long operands, got %s", leftType))
	}
	if !isTypeLong(rightType) && !isTypeUnknown(rightType) {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("comparison operator requires Long operands, got %s", rightType))
	}
	return BoolType{}
}

// typecheckArithmetic handles +, -, * operators
func (ctx *typeContext) typecheckArithmetic(node ast.IsNode) CedarType {
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
			fmt.Sprintf("arithmetic operator requires Long operands, got %s", leftType))
	}
	if !isTypeLong(rightType) && !isTypeUnknown(rightType) {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("arithmetic operator requires Long operands, got %s", rightType))
	}
	return LongType{}
}

// typecheckIn handles the 'in' operator
func (ctx *typeContext) typecheckIn(n ast.NodeTypeIn) CedarType {
	leftType := ctx.typecheck(n.Left)
	rightType := ctx.typecheck(n.Right)

	// Left must be an entity or set of entities
	if !isTypeEntity(leftType) && !isTypeUnknown(leftType) {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("'in' operator left operand must be entity, got %s", leftType))
	}

	// Right must be an entity or set of entities
	if !isTypeEntity(rightType) && !isTypeSet(rightType) && !isTypeUnknown(rightType) {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("'in' operator right operand must be entity or set, got %s", rightType))
	}

	return BoolType{}
}

// typecheckAccess handles attribute access (e.g., principal.name)
func (ctx *typeContext) typecheckAccess(n ast.NodeTypeAccess) CedarType {
	ctx.currentLevel++
	defer func() { ctx.currentLevel-- }()

	if ctx.v.maxAttributeLevel > 0 && ctx.currentLevel > ctx.v.maxAttributeLevel {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("attribute access exceeds maximum level %d (current level: %d)",
				ctx.v.maxAttributeLevel, ctx.currentLevel))
	}

	baseType := ctx.typecheckWithoutLevelIncrement(n.Arg)
	attrName := string(n.Value)

	switch t := baseType.(type) {
	case EntityType:
		return ctx.typecheckEntityAttrAccess(t, attrName)
	case RecordType:
		return ctx.typecheckRecordAttrAccess(t, attrName)
	case UnknownType:
		return UnknownType{}
	default:
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("cannot access attribute '%s' on type %s", attrName, baseType))
		return UnknownType{}
	}
}

// typecheckEntityAttrAccess handles attribute access on entity types.
func (ctx *typeContext) typecheckEntityAttrAccess(t EntityType, attrName string) CedarType {
	info, ok := ctx.v.entityTypes[t.Name]
	if !ok {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("cannot access attribute '%s' on unknown entity type %s", attrName, t.Name))
		return UnknownType{}
	}

	attr, ok := info.Attributes[attrName]
	if !ok {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("entity type %s does not have attribute '%s'", t.Name, attrName))
		return UnknownType{}
	}

	if !attr.Required {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("attribute '%s' on entity type %s is optional; use `has` to check for its presence first", attrName, t.Name))
	}
	return attr.Type
}

// typecheckRecordAttrAccess handles attribute access on record types.
func (ctx *typeContext) typecheckRecordAttrAccess(t RecordType, attrName string) CedarType {
	attr, ok := t.Attributes[attrName]
	if !ok {
		return UnknownType{}
	}

	if !attr.Required {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("attribute '%s' is optional; use `has` to check for its presence first", attrName))
	}
	return attr.Type
}

// typecheckWithoutLevelIncrement is used for nested access to avoid double counting
func (ctx *typeContext) typecheckWithoutLevelIncrement(node ast.IsNode) CedarType {
	if node == nil {
		return UnknownType{}
	}

	// For nested access nodes, delegate to typecheckAccess which handles its own level
	if n, ok := node.(ast.NodeTypeAccess); ok {
		return ctx.typecheckAccess(n)
	}

	// For all other nodes, use regular typecheck
	return ctx.typecheck(node)
}

// typecheckSetOp handles contains, containsAll, containsAny
func (ctx *typeContext) typecheckSetOp(node ast.IsNode) CedarType {
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
			fmt.Sprintf("set operation requires Set operand, got %s", leftType))
	}

	_ = rightType // Right operand type depends on the specific operation
	return BoolType{}
}

// typecheckExtensionCall handles extension function calls
func (ctx *typeContext) typecheckExtensionCall(n ast.NodeTypeExtensionCall) CedarType {
	// Type-check all arguments and collect their types
	argTypes := make([]CedarType, len(n.Args))
	for i, arg := range n.Args {
		argTypes[i] = ctx.typecheck(arg)
	}

	funcName := string(n.Name)

	// Validate argument types and determine return type based on function name
	switch funcName {
	// IP address constructor: ip(String) -> ipaddr
	case "ip", "ipaddr":
		ctx.expectArgs(funcName, argTypes, StringType{})
		// Validate IP address literal if argument is a literal string
		ctx.validateExtensionLiteral(n.Args, "ip", isValidIPLiteral)
		return ExtensionType{Name: "ipaddr"}

	// IP address methods (called on ipaddr, no additional args)
	case "isIpv4", "isIpv6", "isLoopback", "isMulticast":
		ctx.expectArgs(funcName, argTypes, ExtensionType{Name: "ipaddr"})
		return BoolType{}

	// isInRange: ipaddr.isInRange(ipaddr) -> Bool
	case "isInRange":
		ctx.expectArgs(funcName, argTypes, ExtensionType{Name: "ipaddr"}, ExtensionType{Name: "ipaddr"})
		return BoolType{}

	// Decimal constructor: decimal(String) -> decimal
	case "decimal":
		ctx.expectArgs(funcName, argTypes, StringType{})
		ctx.validateExtensionLiteral(n.Args, "decimal", isValidDecimalLiteral)
		return ExtensionType{Name: "decimal"}

	// Decimal comparison methods: decimal.lessThan(decimal) -> Bool
	case "lessThan", "lessThanOrEqual", "greaterThan", "greaterThanOrEqual":
		ctx.expectArgs(funcName, argTypes, ExtensionType{Name: "decimal"}, ExtensionType{Name: "decimal"})
		return BoolType{}

	// Datetime constructor: datetime(String) -> datetime
	case "datetime":
		ctx.expectArgs(funcName, argTypes, StringType{})
		ctx.validateExtensionLiteral(n.Args, "datetime", isValidDatetimeLiteral)
		return ExtensionType{Name: "datetime"}

	// Duration constructor: duration(String) -> duration
	case "duration":
		ctx.expectArgs(funcName, argTypes, StringType{})
		ctx.validateExtensionLiteral(n.Args, "duration", isValidDurationLiteral)
		return ExtensionType{Name: "duration"}

	// Datetime arithmetic: datetime.offset(duration) -> datetime
	case "offset":
		ctx.expectArgs(funcName, argTypes, ExtensionType{Name: "datetime"}, ExtensionType{Name: "duration"})
		return ExtensionType{Name: "datetime"}

	// Datetime difference: datetime.durationSince(datetime) -> duration
	case "durationSince":
		ctx.expectArgs(funcName, argTypes, ExtensionType{Name: "datetime"}, ExtensionType{Name: "datetime"})
		return ExtensionType{Name: "duration"}

	// Datetime extraction methods (called on datetime, no additional args)
	case "toDate", "toTime":
		ctx.expectArgs(funcName, argTypes, ExtensionType{Name: "datetime"})
		return ExtensionType{Name: "datetime"}

	// Duration conversion methods (called on duration, no additional args)
	case "toDays", "toHours", "toMinutes", "toSeconds", "toMilliseconds":
		ctx.expectArgs(funcName, argTypes, ExtensionType{Name: "duration"})
		return LongType{}

	default:
		return UnknownType{}
	}
}

// expectArgs validates that the provided argument types match the expected types.
// If there's a mismatch, it reports a type error.
func (ctx *typeContext) expectArgs(funcName string, actual []CedarType, expected ...CedarType) {
	if len(actual) != len(expected) {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("%s() expects %d argument(s), got %d", funcName, len(expected), len(actual)))
		return
	}

	for i, exp := range expected {
		act := actual[i]
		if !isTypeUnknown(act) && !TypesMatch(exp, act) {
			ctx.errors = append(ctx.errors,
				fmt.Sprintf("%s() argument %d: expected %s, got %s", funcName, i+1, exp, act))
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
