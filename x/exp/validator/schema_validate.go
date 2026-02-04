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
	"strings"

	"github.com/cedar-policy/cedar-go/types"
)

// SchemaValidationError represents schema well-formedness errors.
type SchemaValidationError struct {
	Errors []string
}

func (e *SchemaValidationError) Error() string {
	return strings.Join(e.Errors, "; ")
}

// validateSchemaWellFormedness checks that the parsed schema is well-formed.
// This is called during Validator creation, after the schema has been parsed.
// It validates:
// - Entity types referenced in memberOfTypes exist
// - Entity types referenced in principalTypes/resourceTypes exist (unless allowUnknownEntityTypes)
//
// Note: Cycles in memberOfTypes are NOT checked here. Cedar Rust and Lean allow
// cycles in entity type hierarchies because memberOfTypes defines allowed parent
// types, not actual parent instances. Actual cycle detection happens at entity
// loading time.
//
// Note: Duplicate types in principalTypes/resourceTypes/memberOfTypes are allowed
// (they are semantically redundant but not invalid). This matches Lean's behavior.
func (v *Validator) validateSchemaWellFormedness() error {
	var errors []string

	// Note: We do NOT check for cycles in memberOfTypes. Cedar Rust and Lean
	// allow cycles in entity type hierarchies (e.g., A -> B -> A) because:
	// 1. This defines allowed parent types, not actual parent instances
	// 2. Actual cycle detection happens at entity loading time, not schema time
	// 3. Cycles in types enable valid patterns like mutual group membership

	// Check that referenced types exist (unless in Lean compatibility mode)
	if !v.allowUnknownEntityTypes {
		errors = append(errors, v.checkMemberOfTypesExist()...)
	}
	errors = append(errors, v.checkActionTypesExist()...)

	if len(errors) > 0 {
		return &SchemaValidationError{Errors: errors}
	}
	return nil
}

// checkMemberOfTypesExist validates that all memberOfTypes reference existing entity types.
func (v *Validator) checkMemberOfTypesExist() []string {
	var errors []string
	for entityType, info := range v.entityTypes {
		for _, mot := range info.MemberOfTypes {
			if _, exists := v.entityTypes[mot]; !exists {
				errors = append(errors, fmt.Sprintf("entity type %s references unknown memberOfTypes: %s", entityType, mot))
			}
		}
	}
	return errors
}

// checkActionTypesExist validates that principalTypes and resourceTypes reference existing entity types.
// This check is skipped if allowUnknownEntityTypes is true (Lean compatibility mode).
func (v *Validator) checkActionTypesExist() []string {
	if v.allowUnknownEntityTypes {
		return nil // Skip validation in Lean compatibility mode
	}
	var errors []string
	for actionName, info := range v.actionTypes {
		errors = append(errors, v.checkPrincipalTypesExist(actionName, info.PrincipalTypes)...)
		errors = append(errors, v.checkResourceTypesExist(actionName, info.ResourceTypes)...)
	}
	return errors
}

// checkPrincipalTypesExist validates that all principalTypes for an action exist.
func (v *Validator) checkPrincipalTypesExist(actionName types.EntityUID, principalTypes []types.EntityType) []string {
	var errors []string
	for _, pt := range principalTypes {
		if _, exists := v.entityTypes[pt]; !exists {
			errors = append(errors, fmt.Sprintf("action %s references unknown principalType: %s", actionName, pt))
		}
	}
	return errors
}

// checkResourceTypesExist validates that all resourceTypes for an action exist.
func (v *Validator) checkResourceTypesExist(actionName types.EntityUID, resourceTypes []types.EntityType) []string {
	var errors []string
	for _, rt := range resourceTypes {
		if _, exists := v.entityTypes[rt]; !exists {
			errors = append(errors, fmt.Sprintf("action %s references unknown resourceType: %s", actionName, rt))
		}
	}
	return errors
}
