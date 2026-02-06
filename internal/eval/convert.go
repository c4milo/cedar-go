package eval

import (
	"fmt"

	"github.com/cedar-policy/cedar-go/internal/consts"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
)

// ToEval converts an AST node to an Evaler for evaluation.
func ToEval(n ast.IsNode) Evaler {
	// Try unary operations first
	if e := convertUnaryNode(n); e != nil {
		return e
	}
	// Try binary operations
	if e := convertBinaryNode(n); e != nil {
		return e
	}
	// Handle special nodes
	return convertSpecialNode(n)
}

// convertUnaryNode handles AST nodes with a single argument.
// Returns nil if the node is not a unary operation.
func convertUnaryNode(n ast.IsNode) Evaler {
	switch v := n.(type) {
	case ast.NodeTypeAccess:
		return newAttributeAccessEval(ToEval(v.Arg), v.Value)
	case ast.NodeTypeHas:
		return newHasEval(ToEval(v.Arg), v.Value)
	case ast.NodeTypeLike:
		return newLikeEval(ToEval(v.Arg), v.Value)
	case ast.NodeTypeNegate:
		return newNegateEval(ToEval(v.Arg))
	case ast.NodeTypeNot:
		return newNotEval(ToEval(v.Arg))
	case ast.NodeTypeIsEmpty:
		return newIsEmptyEval(ToEval(v.Arg))
	default:
		return nil
	}
}

// convertBinaryNode handles AST nodes with two arguments.
// Returns nil if the node is not a binary operation.
func convertBinaryNode(n ast.IsNode) Evaler {
	switch v := n.(type) {
	// Tag operations
	case ast.NodeTypeGetTag:
		return newGetTagEval(ToEval(v.Left), ToEval(v.Right))
	case ast.NodeTypeHasTag:
		return newHasTagEval(ToEval(v.Left), ToEval(v.Right))
	// Logical operations
	case ast.NodeTypeIn:
		return newInEval(ToEval(v.Left), ToEval(v.Right))
	case ast.NodeTypeAnd:
		return newAndEval(ToEval(v.Left), ToEval(v.Right))
	case ast.NodeTypeOr:
		return newOrEval(ToEval(v.Left), ToEval(v.Right))
	// Comparison operations
	case ast.NodeTypeEquals:
		return newEqualEval(ToEval(v.Left), ToEval(v.Right))
	case ast.NodeTypeNotEquals:
		return newNotEqualEval(ToEval(v.Left), ToEval(v.Right))
	case ast.NodeTypeGreaterThan:
		return newComparableValueGreaterThanEval(ToEval(v.Left), ToEval(v.Right))
	case ast.NodeTypeGreaterThanOrEqual:
		return newComparableValueGreaterThanOrEqualEval(ToEval(v.Left), ToEval(v.Right))
	case ast.NodeTypeLessThan:
		return newComparableValueLessThanEval(ToEval(v.Left), ToEval(v.Right))
	case ast.NodeTypeLessThanOrEqual:
		return newComparableValueLessThanOrEqualEval(ToEval(v.Left), ToEval(v.Right))
	// Arithmetic operations
	case ast.NodeTypeSub:
		return newSubtractEval(ToEval(v.Left), ToEval(v.Right))
	case ast.NodeTypeAdd:
		return newAddEval(ToEval(v.Left), ToEval(v.Right))
	case ast.NodeTypeMult:
		return newMultiplyEval(ToEval(v.Left), ToEval(v.Right))
	// Set operations
	case ast.NodeTypeContains:
		return newContainsEval(ToEval(v.Left), ToEval(v.Right))
	case ast.NodeTypeContainsAll:
		return newContainsAllEval(ToEval(v.Left), ToEval(v.Right))
	case ast.NodeTypeContainsAny:
		return newContainsAnyEval(ToEval(v.Left), ToEval(v.Right))
	default:
		return nil
	}
}

// convertSpecialNode handles AST nodes that require special conversion logic.
func convertSpecialNode(n ast.IsNode) Evaler {
	switch v := n.(type) {
	case ast.NodeTypeIs:
		return newIsEval(ToEval(v.Left), v.EntityType)
	case ast.NodeTypeIsIn:
		return newIsInEval(ToEval(v.Left), v.EntityType, ToEval(v.Entity))
	case ast.NodeTypeIfThenElse:
		return newIfThenElseEval(ToEval(v.If), ToEval(v.Then), ToEval(v.Else))
	case ast.NodeValue:
		return newLiteralEval(v.Value)
	case ast.NodeTypeVariable:
		return convertVariable(v)
	case ast.NodeTypeExtensionCall:
		return convertExtensionCall(v)
	case ast.NodeTypeRecord:
		return convertRecord(v)
	case ast.NodeTypeSet:
		return convertSet(v)
	default:
		panic(fmt.Sprintf("unknown node type %T", v))
	}
}

// convertVariable converts a variable node to an Evaler.
func convertVariable(v ast.NodeTypeVariable) Evaler {
	switch v.Name {
	case consts.Principal, consts.Action, consts.Resource, consts.Context:
		return newVariableEval(v.Name)
	default:
		panic(fmt.Errorf("unknown variable: %v", v.Name))
	}
}

// convertExtensionCall converts an extension call node to an Evaler.
func convertExtensionCall(v ast.NodeTypeExtensionCall) Evaler {
	args := make([]Evaler, len(v.Args))
	for i, a := range v.Args {
		args[i] = ToEval(a)
	}
	return newExtensionEval(v.Name, args)
}

// convertRecord converts a record literal node to an Evaler.
func convertRecord(v ast.NodeTypeRecord) Evaler {
	m := make(map[types.String]Evaler, len(v.Elements))
	for _, e := range v.Elements {
		m[e.Key] = ToEval(e.Value)
	}
	return newRecordLiteralEval(m)
}

// convertSet converts a set literal node to an Evaler.
func convertSet(v ast.NodeTypeSet) Evaler {
	s := make([]Evaler, len(v.Elements))
	for i, e := range v.Elements {
		s[i] = ToEval(e)
	}
	return newSetLiteralEval(s)
}
