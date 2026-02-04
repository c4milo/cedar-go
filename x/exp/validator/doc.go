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

// Package validator provides static type-checking validation for Cedar policies,
// entities, and requests against a schema.
//
// # Schema Well-Formedness
//
// Creating a Validator validates schema well-formedness:
//   - Entity types referenced in memberOfTypes must exist
//   - Entity types in principalTypes/resourceTypes must exist
//   - No duplicate entity types (handled at parse time)
//
// Use [WithAllowUnknownEntityTypes] for lenient mode that allows unknown types.
//
// # Policy Validation
//
// [ValidatePolicies] checks that all policies in a PolicySet are well-typed
// according to a schema. This catches type errors before authorization:
//
//	result := validator.ValidatePolicies(schema, policies)
//	if !result.Valid {
//	    for _, err := range result.Errors {
//	        fmt.Printf("Policy %s: %s\n", err.PolicyID, err.Message)
//	    }
//	}
//
// Policy validation includes:
//   - Type checking of expressions in when/unless clauses
//   - Scope validation (principal/resource types match action constraints)
//   - Optional attribute access warnings (use "has" to check first)
//   - Impossible policy detection (policy can never match any request)
//
// # Entity Validation
//
// [ValidateEntities] checks that all entities conform to the schema:
//
//   - Entity types must be defined in the schema
//   - Attributes must match declared types
//   - Required attributes must be present
//   - Parent relationships must follow memberOfTypes constraints
//
// Example:
//
//	result := validator.ValidateEntities(schema, entities)
//	if !result.Valid {
//	    for _, err := range result.Errors {
//	        fmt.Printf("Entity %s: %s\n", err.EntityUID, err.Message)
//	    }
//	}
//
// Use [WithStrictEntityValidation] to also reject entities with attributes
// not declared in the schema.
//
// # Request Validation
//
// [ValidateRequest] checks that a request matches the schema:
//
//   - Principal type must be valid for the action
//   - Resource type must be valid for the action
//   - Context must match the action's declared context type
//
// Example:
//
//	result := validator.ValidateRequest(schema, request)
//	if !result.Valid {
//	    fmt.Printf("Request error: %s\n", result.Error)
//	}
package validator
