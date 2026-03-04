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

import "fmt"

// ValidationErrorCode represents a category of validation error.
// These codes provide structured error identification for programmatic handling.
type ValidationErrorCode string

const (
	// Policy structure errors

	// ErrImpossiblePolicy indicates a policy that can never match any valid request.
	// This includes policies with:
	// - Impossible scope combinations (e.g., principal type not allowed for action)
	// - Conditions that always evaluate to false (e.g., when { false })
	// - Empty action sets (e.g., action in [])
	ErrImpossiblePolicy ValidationErrorCode = "impossible_policy"

	// ErrInvalidScope indicates an invalid scope constraint in a policy.
	ErrInvalidScope ValidationErrorCode = "invalid_scope"

	// Type errors

	// ErrUnexpectedType indicates a type mismatch in an expression.
	// For example, using a string where a boolean is expected.
	ErrUnexpectedType ValidationErrorCode = "unexpected_type"

	// ErrTypeMismatch indicates incompatible types in an operation.
	// For example, comparing a boolean with a string using ==.
	ErrTypeMismatch ValidationErrorCode = "type_mismatch"

	// ErrEmptySet indicates an empty set literal that cannot have its type inferred.
	ErrEmptySet ValidationErrorCode = "empty_set"

	// ErrIncompatibleTypes indicates set elements or branch types that are incompatible.
	ErrIncompatibleTypes ValidationErrorCode = "incompatible_types"

	// Entity errors

	// ErrUnknownEntity indicates a reference to an entity type not defined in the schema.
	ErrUnknownEntity ValidationErrorCode = "unknown_entity"

	// ErrUnknownAction indicates a reference to an action not defined in the schema.
	ErrUnknownAction ValidationErrorCode = "unknown_action"

	// ErrInvalidParent indicates an entity has a parent of a type not allowed by memberOfTypes.
	ErrInvalidParent ValidationErrorCode = "invalid_parent"

	// Attribute errors

	// ErrAttributeNotFound indicates an attempt to access an attribute that doesn't exist.
	ErrAttributeNotFound ValidationErrorCode = "attribute_not_found"

	// ErrAttributeAccess indicates an error in attribute access, such as accessing
	// an optional attribute without checking with `has` first.
	ErrAttributeAccess ValidationErrorCode = "attribute_access"

	// ErrLevelExceeded indicates attribute access depth exceeded the configured maximum.
	// This is related to RFC 76 level-based validation.
	ErrLevelExceeded ValidationErrorCode = "level_exceeded"

	// Extension errors

	// ErrExtensionCall indicates an error in an extension function call,
	// such as wrong argument count or invalid argument types.
	ErrExtensionCall ValidationErrorCode = "extension_error"

	// ErrInvalidLiteral indicates an invalid literal value for an extension type,
	// such as an invalid IP address or decimal format.
	ErrInvalidLiteral ValidationErrorCode = "invalid_literal"

	// Schema errors

	// ErrMissingAttribute indicates a required attribute is missing from an entity.
	ErrMissingAttribute ValidationErrorCode = "missing_attribute"

	// ErrUndeclaredAttribute indicates an attribute that is not declared in the schema
	// (only reported in strict validation mode).
	ErrUndeclaredAttribute ValidationErrorCode = "undeclared_attribute"
)

// ValidationError provides structured error information for validation failures.
// It includes an error code for programmatic handling, a human-readable message,
// and optional structured details.
type ValidationError struct {
	// Code is the error category for programmatic handling.
	Code ValidationErrorCode

	// Message is a human-readable description of the error.
	Message string

	// Details contains optional structured information about the error.
	// Common keys include:
	// - "entityType": the entity type involved
	// - "attribute": the attribute name
	// - "expected": expected type or value
	// - "actual": actual type or value
	Details map[string]string
}

// Error implements the error interface.
func (e ValidationError) Error() string {
	if e.Code == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}
