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
)

// PolicyValidationResult contains the result of validating policies.
type PolicyValidationResult struct {
	Valid  bool
	Errors []PolicyError
}

// PolicyError represents a validation error for a specific policy.
type PolicyError struct {
	PolicyID cedar.PolicyID
	Message  string
	// Code is an optional structured error code for programmatic handling.
	// This field is being gradually populated across the codebase.
	Code ValidationErrorCode
}

// EntityValidationResult contains the result of validating entities.
type EntityValidationResult struct {
	Valid  bool
	Errors []EntityError
}

// EntityError represents a validation error for a specific entity.
type EntityError struct {
	EntityUID types.EntityUID
	Message   string
	// Code is an optional structured error code for programmatic handling.
	// This field is being gradually populated across the codebase.
	Code ValidationErrorCode
}

// RequestValidationResult contains the result of validating a request.
type RequestValidationResult struct {
	Valid bool
	Error string
}
