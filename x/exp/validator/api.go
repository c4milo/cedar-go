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
	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
)

// ValidatePolicies validates all policies in a PolicySet against a schema.
// This is a convenience function that creates a Validator and validates policies.
//
// Options can be provided to configure the validator behavior:
//
//	// Validate with attribute level checking (RFC 76)
//	result := validator.ValidatePolicies(schema, policies, validator.WithMaxAttributeLevel(2))
//
// Example:
//
//	result := validator.ValidatePolicies(schema, policies)
//	if !result.Valid {
//	    for _, err := range result.Errors {
//	        log.Printf("Policy %s: %s", err.PolicyID, err.Message)
//	    }
//	}
func ValidatePolicies(s *schema.Schema, policies *cedar.PolicySet, opts ...ValidatorOption) PolicyValidationResult {
	v, err := New(s, opts...)
	if err != nil {
		return PolicyValidationResult{
			Valid:  false,
			Errors: []PolicyError{{Message: err.Error()}},
		}
	}
	return v.ValidatePolicies(policies)
}

// ValidateEntities validates all entities against a schema.
// This is a convenience function that creates a Validator and validates entities.
//
// Options can be provided to configure the validator behavior:
//
//	// Validate with strict mode to catch undeclared attributes
//	result := validator.ValidateEntities(schema, entities, validator.WithStrictEntityValidation())
//
// Example:
//
//	result := validator.ValidateEntities(schema, entities)
//	if !result.Valid {
//	    for _, err := range result.Errors {
//	        log.Printf("Entity %s: %s", err.EntityUID, err.Message)
//	    }
//	}
func ValidateEntities(s *schema.Schema, entities types.EntityMap, opts ...ValidatorOption) EntityValidationResult {
	v, err := New(s, opts...)
	if err != nil {
		return EntityValidationResult{
			Valid:  false,
			Errors: []EntityError{{Message: err.Error()}},
		}
	}
	return v.ValidateEntities(entities)
}

// ValidateRequest validates a request against a schema.
// This is a convenience function that creates a Validator and validates a request.
//
// Example:
//
//	result := validator.ValidateRequest(schema, request)
//	if !result.Valid {
//	    log.Printf("Request error: %s", result.Error)
//	}
func ValidateRequest(s *schema.Schema, req cedar.Request) RequestValidationResult {
	v, err := New(s)
	if err != nil {
		return RequestValidationResult{
			Valid: false,
			Error: err.Error(),
		}
	}
	return v.ValidateRequest(req)
}
