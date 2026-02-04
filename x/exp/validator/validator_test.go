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
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
)

// Core validator tests and test helpers.

// policyResultAsserter helps verify PolicyValidationResult fields.
type policyResultAsserter struct {
	t      *testing.T
	result PolicyValidationResult
}

func assertPolicyResult(t *testing.T, result PolicyValidationResult) *policyResultAsserter {
	return &policyResultAsserter{t: t, result: result}
}

func (a *policyResultAsserter) valid() *policyResultAsserter {
	a.t.Helper()
	if !a.result.Valid {
		a.t.Errorf("Expected valid, got errors: %v", a.result.Errors)
	}
	return a
}

func (a *policyResultAsserter) invalid() *policyResultAsserter {
	a.t.Helper()
	if a.result.Valid {
		a.t.Error("Expected invalid, but validation passed")
	}
	return a
}

func (a *policyResultAsserter) errorContains(substr string) *policyResultAsserter {
	a.t.Helper()
	for _, err := range a.result.Errors {
		if strings.Contains(err.Message, substr) {
			return a
		}
	}
	a.t.Errorf("Expected error containing %q, got: %v", substr, a.result.Errors)
	return a
}

// validatePolicyString is a helper that parses and validates a policy.
func validatePolicyString(t *testing.T, s *schema.Schema, policyStr string) PolicyValidationResult {
	t.Helper()
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(policyStr)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)
	return ValidatePolicies(s, policies)
}

// checkPolicyResult checks policy validation results against expectations.
func checkPolicyResult(t *testing.T, result PolicyValidationResult, wantValid bool, wantError string) {
	t.Helper()
	if wantValid {
		if !result.Valid {
			t.Errorf("Expected valid, got errors: %v", result.Errors)
		}
		return
	}
	if result.Valid {
		t.Error("Expected invalid, but validation passed")
		return
	}
	if wantError == "" {
		return
	}
	for _, err := range result.Errors {
		if strings.Contains(err.Message, wantError) {
			return
		}
	}
	t.Errorf("Expected error containing %q, got: %v", wantError, result.Errors)
}

func TestValidatePolicies(t *testing.T) {

	schemaJSON := `{
		"entityTypes": {
			"User": {},
			"Document": {}
		},
		"actions": {
			"view": {
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["Document"]
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid policies, got errors: %v", result.Errors)
	}
}

func TestRecordAttributesMatchAdditional(t *testing.T) {

	expected := RecordType{
		Attributes: map[string]AttributeType{
			"name":  {Type: StringType{}, Required: true},
			"email": {Type: StringType{}, Required: false},
		},
	}
	actual := RecordType{
		Attributes: map[string]AttributeType{
			"name": {Type: StringType{}, Required: true},
		},
	}
	if !TypesMatch(expected, actual) {
		t.Error("Expected match when optional attribute is missing")
	}

	expected2 := RecordType{
		Attributes: map[string]AttributeType{
			"count": {Type: LongType{}, Required: true},
		},
	}
	actual2 := RecordType{
		Attributes: map[string]AttributeType{
			"count": {Type: StringType{}, Required: true},
		},
	}
	if TypesMatch(expected2, actual2) {
		t.Error("Expected no match when attribute types differ")
	}

	expected3 := RecordType{
		Attributes: map[string]AttributeType{
			"required": {Type: StringType{}, Required: true},
		},
	}
	actual3 := RecordType{
		Attributes: map[string]AttributeType{},
	}
	if TypesMatch(expected3, actual3) {
		t.Error("Expected no match when required attribute is missing")
	}
}

func TestCheckEntityTypeKnown(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {},
				"Document": {}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					}
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal == User::"alice", action, resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid for known entity type, got errors: %v", result.Errors)
	}

	// Test with Action type (special case, should not error)
	var policy2 cedar.Policy
	if err := policy2.UnmarshalCedar([]byte(`permit(principal, action in Action::"view", resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies2 := cedar.NewPolicySet()
	policies2.Add("test2", &policy2)

	result = ValidatePolicies(s, policies2)
	if !result.Valid {
		t.Errorf("Expected valid for Action type, got errors: %v", result.Errors)
	}
}

func TestConditionMustBeBoolean(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"name": {"type": "String"}
						}
					}
				}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["User"]
					}
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.name };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if result.Valid {
		t.Error("Expected invalid when condition is not boolean")
	}
}

func TestParseJSONTypeVariants(t *testing.T) {

	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"flag": {"type": "Boolean"},
							"flagAlt": {"type": "Bool"},
							"num": {"type": "Long"},
							"text": {"type": "String"},
							"entity": {"type": "Entity", "name": "User"},
							"anyEntity": {"type": "Entity"},
							"items": {"type": "Set", "element": {"type": "String"}},
							"emptySet": {"type": "Set"},
							"record": {"type": "Record", "attributes": {}},
							"ext": {"type": "Extension", "name": "decimal"},
							"extUnnamed": {"type": "Extension"}
						}
					}
				}
			},
			"actions": {}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	_, err = New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}
}

func TestAllEntityTypesPath(t *testing.T) {

	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {},
				"Admin": {},
				"Document": {}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User", "Admin"],
						"resourceTypes": ["Document"]
					}
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestCheckEntityTypeWithAction(t *testing.T) {

	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {},
				"Document": {}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					}
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal == User::"alice", action == Action::"view", resource == Document::"doc1");`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

// TestLevelBasedValidation tests RFC 76 level-based validation
func TestLevelBasedValidation(t *testing.T) {

	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"name": {"type": "String", "required": true},
							"manager": {"type": "Entity", "name": "User", "required": true},
							"department": {"type": "Entity", "name": "Department", "required": true}
						}
					}
				},
				"Department": {
					"shape": {
						"type": "Record",
						"attributes": {
							"name": {"type": "String", "required": true},
							"head": {"type": "Entity", "name": "User", "required": true}
						}
					}
				},
				"Document": {}
			},
			"actions": {
				"read": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					}
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name      string
		policy    string
		maxLevel  int
		wantValid bool
		wantError string
	}{
		{
			name:      "level_1_within_limit",
			policy:    `permit(principal, action == Action::"read", resource) when { principal.name == "alice" };`,
			maxLevel:  1,
			wantValid: true,
		},
		{
			name:      "level_2_within_limit",
			policy:    `permit(principal, action == Action::"read", resource) when { principal.manager.name == "bob" };`,
			maxLevel:  2,
			wantValid: true,
		},
		{
			name:      "level_2_exceeds_limit_1",
			policy:    `permit(principal, action == Action::"read", resource) when { principal.manager.name == "bob" };`,
			maxLevel:  1,
			wantValid: false,
			wantError: "exceeds maximum level 1",
		},
		{
			name:      "level_3_exceeds_limit_2",
			policy:    `permit(principal, action == Action::"read", resource) when { principal.department.head.name == "ceo" };`,
			maxLevel:  2,
			wantValid: false,
			wantError: "exceeds maximum level 2",
		},
		{
			name:      "level_3_within_limit_3",
			policy:    `permit(principal, action == Action::"read", resource) when { principal.department.head.name == "ceo" };`,
			maxLevel:  3,
			wantValid: true,
		},
		{
			name:      "no_limit_allows_deep_access",
			policy:    `permit(principal, action == Action::"read", resource) when { principal.department.head.name == "ceo" };`,
			maxLevel:  0,
			wantValid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policies := cedar.NewPolicySet()
			var policy cedar.Policy
			if err := policy.UnmarshalCedar([]byte(tc.policy)); err != nil {
				t.Fatalf("Failed to parse policy: %v", err)
			}
			policies.Add("test", &policy)

			result := ValidatePolicies(s, policies, WithMaxAttributeLevel(tc.maxLevel))
			checkPolicyResult(t, result, tc.wantValid, tc.wantError)
		})
	}
}

func TestWithMaxAttributeLevelOption(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"name": {"type": "String"}
						}
					}
				}
			},
			"actions": {}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(s, WithMaxAttributeLevel(2))
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	if v.maxAttributeLevel != 2 {
		t.Errorf("Expected maxAttributeLevel=2, got %d", v.maxAttributeLevel)
	}

	v2, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	if v2.maxAttributeLevel != 0 {
		t.Errorf("Expected default maxAttributeLevel=0, got %d", v2.maxAttributeLevel)
	}
}

// TestNamespacedActions tests that actions in namespaced schemas are stored
// with the correct qualified action type (e.g., MyApp::Action::"view").
func TestNamespacedActions(t *testing.T) {
	schemaJSON := `{
		"MyApp": {
			"entityTypes": {
				"User": {},
				"Document": {}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					}
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	expectedActionUID := types.EntityUID{Type: "MyApp::Action", ID: "view"}
	if _, ok := v.actionTypes[expectedActionUID]; !ok {
		t.Errorf("Expected action with type MyApp::Action not found")
		t.Logf("Available actions:")
		for uid := range v.actionTypes {
			t.Logf("  %s", uid)
		}
	}

	unqualifiedActionUID := types.EntityUID{Type: "Action", ID: "view"}
	if _, ok := v.actionTypes[unqualifiedActionUID]; ok {
		t.Errorf("Action should not be stored with unqualified 'Action' type")
	}
}

// TestNamespacedActionValidation tests policy validation with namespaced actions.
func TestNamespacedActionValidation(t *testing.T) {
	schemaJSON := `{
		"MyApp": {
			"entityTypes": {
				"User": {},
				"Document": {}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					}
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action == MyApp::Action::"view", resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid policy, got errors: %v", result.Errors)
	}
}

// TestOpenRecordAllowsExtraAttributes tests that entities with no shape definition
// allow extra attributes even in strict mode (entities without a shape are open by default).
func TestOpenRecordAllowsExtraAttributes(t *testing.T) {

	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {}
			},
			"actions": {}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "alice"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"name":       types.String("Alice"),
				"extraField": types.String("allowed because no shape means open"),
			}),
		},
	}

	result := ValidateEntities(s, entities, WithStrictEntityValidation())
	if !result.Valid {
		t.Errorf("Entity without shape should allow extra attributes even in strict mode, got errors: %v", result.Errors)
	}
}

// TestClosedRecordRejectsExtraAttributes tests that schemas with additionalAttributes=false
// reject extra attributes in strict mode.
func TestClosedRecordRejectsExtraAttributes(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"name": {"type": "String", "required": true}
						},
						"additionalAttributes": false
					}
				}
			},
			"actions": {}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "alice"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"name":       types.String("Alice"),
				"extraField": types.String("should be rejected"),
			}),
		},
	}

	result := ValidateEntities(s, entities, WithStrictEntityValidation())
	if result.Valid {
		t.Error("Closed record should reject extra attributes in strict mode")
	}
}

// TestExtensionFunctionArgumentValidation tests that extension functions
// validate their argument types.
func TestExtensionFunctionArgumentValidation(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"ip": {"type": "Extension", "name": "ipaddr"},
							"count": {"type": "Long"}
						}
					}
				}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["User"]
					}
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name        string
		policy      string
		expectValid bool
		errorSubstr string
	}{
		{
			name:        "valid ip() with String",
			policy:      `permit(principal, action, resource) when { ip("192.168.1.1").isIpv4() };`,
			expectValid: true,
		},
		{
			name:        "invalid ip() with Long",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { ip(principal.count).isIpv4() };`,
			expectValid: false,
			errorSubstr: "expected String",
		},
		{
			name:        "valid decimal() with String",
			policy:      `permit(principal, action, resource) when { decimal("1.5").lessThan(decimal("2.0")) };`,
			expectValid: true,
		},
		{
			name:        "invalid decimal() with Long",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { decimal(principal.count).lessThan(decimal("2.0")) };`,
			expectValid: false,
			errorSubstr: "expected String",
		},
		{
			name:        "valid datetime() with String",
			policy:      `permit(principal, action, resource) when { datetime("2024-01-01T00:00:00Z").toDate() == datetime("2024-01-01T00:00:00Z") };`,
			expectValid: true,
		},
		{
			name:        "valid duration() with String",
			policy:      `permit(principal, action, resource) when { duration("1h").toSeconds() > 0 };`,
			expectValid: true,
		},
		{
			name:        "valid isInRange with two ipaddrs",
			policy:      `permit(principal, action, resource) when { ip("192.168.1.1").isInRange(ip("192.168.0.0/16")) };`,
			expectValid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := validatePolicyString(t, s, tc.policy)
			a := assertPolicyResult(t, result)
			if tc.expectValid {
				a.valid()
			} else {
				a.invalid()
				if tc.errorSubstr != "" {
					a.errorContains(tc.errorSubstr)
				}
			}
		})
	}
}

// TestCommonTypes tests schema with common type definitions.
func TestCommonTypes(t *testing.T) {
	schemaJSON := `{
		"": {
			"commonTypes": {
				"Address": {
					"type": "Record",
					"attributes": {
						"street": {"type": "String"},
						"city": {"type": "String"}
					}
				}
			},
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"name": {"type": "String"},
							"address": {"type": "Address"}
						}
					}
				}
			},
			"actions": {}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	if _, ok := v.commonTypes["Address"]; !ok {
		t.Error("Expected common type 'Address' to be defined")
	}

	userInfo, ok := v.entityTypes["User"]
	if !ok {
		t.Fatal("User entity type not found")
	}

	if _, hasAddress := userInfo.Attributes["address"]; !hasAddress {
		t.Error("Expected User to have 'address' attribute")
	}
}

// TestExtensionFunctionArgCountErrors tests that extension functions
// report errors for wrong argument counts.
func TestExtensionFunctionArgCountErrors(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["User"]
					}
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { decimal("1.0").lessThan(decimal("2.0")) };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)

	if !result.Valid {
		t.Errorf("Expected valid policy, got errors: %v", result.Errors)
	}
}

// TestConditionalExpressions tests if-then-else expression validation.
func TestConditionalExpressions(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"active": {"type": "Boolean", "required": true},
							"level": {"type": "Long", "required": true}
						}
					}
				}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["User"]
					}
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name        string
		policy      string
		expectValid bool
		errorSubstr string
	}{
		{
			name:        "valid if-then-else",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { if principal.active then principal.level > 0 else false };`,
			expectValid: true,
		},
		{
			name:        "if condition must be boolean",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { if principal.level then true else false };`,
			expectValid: false,
			errorSubstr: "boolean",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := validatePolicyString(t, s, tc.policy)
			a := assertPolicyResult(t, result)
			if tc.expectValid {
				a.valid()
			} else {
				a.invalid()
				if tc.errorSubstr != "" {
					a.errorContains(tc.errorSubstr)
				}
			}
		})
	}
}

// TestEntityTypeReference tests entity type references in attributes.
func TestEntityTypeReference(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"manager": {"type": "Entity", "name": "User"},
							"department": {"type": "Entity", "name": "Department"}
						}
					}
				},
				"Department": {}
			},
			"actions": {}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	userInfo, ok := v.entityTypes["User"]
	if !ok {
		t.Fatal("User entity type not found")
	}

	managerAttr, ok := userInfo.Attributes["manager"]
	if !ok {
		t.Fatal("manager attribute not found")
	}
	if entityType, ok := managerAttr.Type.(EntityType); ok {
		if entityType.Name != "User" {
			t.Errorf("Expected manager to reference User, got %s", entityType.Name)
		}
	} else {
		t.Errorf("Expected manager to be EntityType, got %T", managerAttr.Type)
	}
}
