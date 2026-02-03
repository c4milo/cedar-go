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

		// Condition must evaluate to Boolean
		if !isTypeBoolean(inferredType) && !isTypeUnknown(inferredType) {
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
		return ctx.v.inferType(n.Value)
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

	ctx.typecheck(left)
	ctx.typecheck(right)
	// Equality is allowed between any types (will evaluate to false if incompatible)
	return BoolType{}
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
	// Increment level before checking the base
	ctx.currentLevel++
	defer func() { ctx.currentLevel-- }()

	// Check if we've exceeded the max attribute level
	if ctx.v.maxAttributeLevel > 0 && ctx.currentLevel > ctx.v.maxAttributeLevel {
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("attribute access exceeds maximum level %d (current level: %d)",
				ctx.v.maxAttributeLevel, ctx.currentLevel))
	}

	baseType := ctx.typecheckWithoutLevelIncrement(n.Arg)
	attrName := string(n.Value)

	switch t := baseType.(type) {
	case EntityType:
		// Look up the attribute in the entity type
		if t.Name != "" {
			if info, ok := ctx.v.entityTypes[t.Name]; ok {
				if attr, ok := info.Attributes[attrName]; ok {
					return attr.Type
				}
				ctx.errors = append(ctx.errors,
					fmt.Sprintf("entity type %s does not have attribute '%s'", t.Name, attrName))
			}
		}
		return UnknownType{}

	case RecordType:
		if attr, ok := t.Attributes[attrName]; ok {
			return attr.Type
		}
		// Record type might allow any attribute if schema is incomplete
		return UnknownType{}

	case UnknownType:
		return UnknownType{}

	default:
		ctx.errors = append(ctx.errors,
			fmt.Sprintf("cannot access attribute '%s' on type %s", attrName, baseType))
		return UnknownType{}
	}
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
	// Type-check all arguments
	for _, arg := range n.Args {
		ctx.typecheck(arg)
	}

	// Determine return type based on function name
	switch string(n.Name) {
	// IP address functions
	case "ip", "ipaddr":
		return ExtensionType{Name: "ipaddr"}
	case "isIpv4", "isIpv6", "isLoopback", "isMulticast", "isInRange":
		return BoolType{}

	// Decimal functions
	case "decimal":
		return ExtensionType{Name: "decimal"}
	case "lessThan", "lessThanOrEqual", "greaterThan", "greaterThanOrEqual":
		return BoolType{}

	// Datetime functions
	case "datetime":
		return ExtensionType{Name: "datetime"}
	case "duration":
		return ExtensionType{Name: "duration"}
	case "offset", "durationSince":
		return ExtensionType{Name: "datetime"}
	case "toDate", "toTime":
		return ExtensionType{Name: "datetime"}
	case "toDays", "toHours", "toMinutes", "toSeconds", "toMilliseconds":
		return LongType{}

	default:
		return UnknownType{}
	}
}

// Helper functions for type checking
func isTypeBoolean(t CedarType) bool {
	_, ok := t.(BoolType)
	return ok
}

func isTypeLong(t CedarType) bool {
	_, ok := t.(LongType)
	return ok
}

func isTypeString(t CedarType) bool {
	_, ok := t.(StringType)
	return ok
}

func isTypeEntity(t CedarType) bool {
	_, ok := t.(EntityType)
	return ok
}

func isTypeSet(t CedarType) bool {
	_, ok := t.(SetType)
	return ok
}

func isTypeUnknown(t CedarType) bool {
	_, ok := t.(UnknownType)
	return ok
}

// unifyTypes returns a type that represents both types
func unifyTypes(t1, t2 CedarType) CedarType {
	if isTypeUnknown(t1) {
		return t2
	}
	if isTypeUnknown(t2) {
		return t1
	}
	if TypesMatch(t1, t2) {
		return t1
	}
	return UnknownType{}
}
