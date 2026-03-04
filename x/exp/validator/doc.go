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
// # Creating a Validator
//
// Use [New] to create a reusable Validator from a schema:
//
//	v, err := validator.New(schema)
//	if err != nil {
//	    // Schema is malformed (cycles, unknown references, etc.)
//	}
//
// The Validator can then be reused to validate multiple policies, entities, and requests.
//
// For one-off validation, use the convenience functions [ValidatePolicies],
// [ValidateEntities], and [ValidateRequest] which create a Validator internally.
//
// # Validator Options
//
// Options can be provided to configure the validator behavior:
//
//   - [WithMaxAttributeLevel]: Limits attribute access depth (RFC 76 level-based validation).
//     Level 1 allows principal.name but not principal.manager.name.
//   - [WithStrictEntityValidation]: Rejects entities with undeclared attributes.
//   - [WithAllowUnknownEntityTypes]: Allows unknown entity types in schema references
//     (matches Lean behavior).
//
// Example with options:
//
//	v, err := validator.New(schema,
//	    validator.WithMaxAttributeLevel(2),
//	    validator.WithStrictEntityValidation(),
//	)
//
// # Schema Well-Formedness
//
// Creating a Validator validates schema well-formedness:
//   - Entity types referenced in memberOfTypes must exist
//   - Entity types in principalTypes/resourceTypes must exist
//   - No cycles in entity hierarchy
//
// Use [WithAllowUnknownEntityTypes] for lenient mode that allows unknown types.
//
// # Policy Validation
//
// [Validator.ValidatePolicies] checks that all policies in a PolicySet are well-typed
// according to a schema. This catches type errors before authorization:
//
//	result := v.ValidatePolicies(policies)
//	if !result.Valid {
//	    for _, err := range result.Errors {
//	        fmt.Printf("Policy %s: %s\n", err.PolicyID, err.Message)
//	    }
//	}
//
// Or use the convenience function:
//
//	result := validator.ValidatePolicies(schema, policies)
//
// Policy validation includes:
//   - Type checking of expressions in when/unless clauses
//   - Scope validation (principal/resource types match action constraints)
//   - Optional attribute access warnings (use "has" to check first)
//   - Impossible policy detection (policy can never match any request)
//
// # Entity Validation
//
// [Validator.ValidateEntities] checks that all entities conform to the schema:
//
//   - Entity types must be defined in the schema
//   - Attributes must match declared types
//   - Required attributes must be present
//   - Parent relationships must follow memberOfTypes constraints
//
// Example:
//
//	result := v.ValidateEntities(entities)
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
// [Validator.ValidateRequest] checks that a request matches the schema:
//
//   - Action must be defined in the schema
//   - Principal type must be valid for the action
//   - Resource type must be valid for the action
//   - Context must match the action's declared context type
//
// Example:
//
//	result := v.ValidateRequest(request)
//	if !result.Valid {
//	    fmt.Printf("Request error: %s\n", result.Error)
//	}
package validator
