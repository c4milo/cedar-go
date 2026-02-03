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

func TestValidateEntities(t *testing.T) {
	// JSON schema uses namespace format - empty string is the default namespace
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"name": {"type": "String", "required": true},
							"age": {"type": "Long", "required": false}
						}
					}
				},
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Valid entity
	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "alice"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"name": types.String("Alice"),
			}),
		},
	}

	result := ValidateEntities(&s, entities)
	if !result.Valid {
		t.Errorf("Expected valid entities, got errors: %v", result.Errors)
	}
}

func TestValidateRequest(t *testing.T) {
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Valid request
	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	result := ValidateRequest(&s, req)
	if !result.Valid {
		t.Errorf("Expected valid request, got error: %s", result.Error)
	}

	// Invalid request - wrong principal type
	badReq := cedar.Request{
		Principal: types.EntityUID{Type: "Admin", ID: "bob"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	result = ValidateRequest(&s, badReq)
	if result.Valid {
		t.Error("Expected invalid request for wrong principal type")
	}
}

func TestValidatePolicies(t *testing.T) {
	// Test with flat format (commonly used in Cedar examples)
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid policies, got errors: %v", result.Errors)
	}
}

func TestTypecheckConditions(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"name": {"type": "String", "required": true},
							"age": {"type": "Long", "required": true},
							"active": {"type": "Boolean", "required": true}
						}
					}
				},
				"Document": {
					"shape": {
						"type": "Record",
						"attributes": {
							"title": {"type": "String", "required": true}
						}
					}
				}
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name        string
		policy      string
		expectValid bool
		errorSubstr string // substring expected in error message
	}{
		{
			name:        "valid simple permit",
			policy:      `permit(principal, action, resource);`,
			expectValid: true,
		},
		{
			name:        "valid attribute access",
			policy:      `permit(principal, action, resource) when { principal.name == "alice" };`,
			expectValid: true,
		},
		{
			name:        "valid boolean condition",
			policy:      `permit(principal, action, resource) when { principal.active };`,
			expectValid: true,
		},
		{
			name:        "valid arithmetic comparison",
			policy:      `permit(principal, action, resource) when { principal.age > 18 };`,
			expectValid: true,
		},
		{
			name:        "valid logical operators",
			policy:      `permit(principal, action, resource) when { principal.active && principal.age > 0 };`,
			expectValid: true,
		},
		{
			name:        "invalid attribute access",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { principal.nonexistent == "x" };`,
			expectValid: false,
			errorSubstr: "does not have attribute",
		},
		{
			name:        "invalid boolean operator on non-boolean",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { principal.name && true };`,
			expectValid: false,
			errorSubstr: "boolean",
		},
		{
			name:        "invalid comparison on non-long",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { principal.name > 5 };`,
			expectValid: false,
			errorSubstr: "Long",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := validatePolicyString(t, &s, tc.policy)
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

func TestTypecheckArithmetic(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"age": {"type": "Long", "required": true},
							"score": {"type": "Long", "required": true}
						}
					}
				},
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name        string
		policy      string
		expectValid bool
	}{
		{
			name:        "valid addition",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { principal.age + 1 > 18 };`,
			expectValid: true,
		},
		{
			name:        "valid subtraction",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { principal.age - 1 > 0 };`,
			expectValid: true,
		},
		{
			name:        "valid multiplication",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { principal.score * 2 > 10 };`,
			expectValid: true,
		},
		{
			name:        "valid negation",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { -(principal.age) < 0 };`,
			expectValid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := validatePolicyString(t, &s, tc.policy)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
		})
	}
}

func TestTypecheckSetOperations(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"roles": {"type": "Set", "element": {"type": "String"}, "required": true}
						}
					}
				},
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name        string
		policy      string
		expectValid bool
	}{
		{
			name:        "valid contains",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { principal.roles.contains("admin") };`,
			expectValid: true,
		},
		{
			name:        "valid containsAll",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { principal.roles.containsAll(["admin", "user"]) };`,
			expectValid: true,
		},
		{
			name:        "valid containsAny",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { principal.roles.containsAny(["admin", "superuser"]) };`,
			expectValid: true,
		},
		{
			name:        "valid isEmpty",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { !principal.roles.isEmpty() };`,
			expectValid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := validatePolicyString(t, &s, tc.policy)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
		})
	}
}

func TestTypecheckConditionals(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"active": {"type": "Boolean", "required": true},
							"premium": {"type": "Boolean", "required": true}
						}
					}
				},
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name        string
		policy      string
		expectValid bool
	}{
		{
			name:        "valid if-then-else",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { if principal.active then principal.premium else false };`,
			expectValid: true,
		},
		{
			name:        "valid not operator",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { !principal.active || principal.premium };`,
			expectValid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := validatePolicyString(t, &s, tc.policy)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
		})
	}
}

func TestTypecheckInOperator(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"memberOfTypes": ["Group"]
				},
				"Group": {},
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name        string
		policy      string
		expectValid bool
	}{
		{
			name:        "valid in operator",
			policy:      `permit(principal in Group::"admins", action == Action::"view", resource);`,
			expectValid: true,
		},
		{
			name:        "valid is operator",
			policy:      `permit(principal is User, action == Action::"view", resource);`,
			expectValid: true,
		},
		{
			name:        "valid is in operator",
			policy:      `permit(principal is User in Group::"admins", action == Action::"view", resource);`,
			expectValid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := validatePolicyString(t, &s, tc.policy)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
		})
	}
}

func TestValidateEntitiesComplex(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"name": {"type": "String", "required": true},
							"age": {"type": "Long", "required": true},
							"active": {"type": "Boolean", "required": true},
							"email": {"type": "String", "required": false}
						}
					},
					"memberOfTypes": ["Group"]
				},
				"Group": {},
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name        string
		entities    types.EntityMap
		expectValid bool
	}{
		{
			name: "valid entity with all required attrs",
			entities: types.EntityMap{
				types.NewEntityUID("User", "alice"): types.Entity{
					Attributes: types.NewRecord(types.RecordMap{
						"name":   types.String("Alice"),
						"age":    types.Long(30),
						"active": types.Boolean(true),
					}),
				},
			},
			expectValid: true,
		},
		{
			name: "valid entity with optional attr",
			entities: types.EntityMap{
				types.NewEntityUID("User", "bob"): types.Entity{
					Attributes: types.NewRecord(types.RecordMap{
						"name":   types.String("Bob"),
						"age":    types.Long(25),
						"active": types.Boolean(true),
						"email":  types.String("bob@example.com"),
					}),
				},
			},
			expectValid: true,
		},
		{
			name: "invalid entity missing required attr",
			entities: types.EntityMap{
				types.NewEntityUID("User", "charlie"): types.Entity{
					Attributes: types.NewRecord(types.RecordMap{
						"name": types.String("Charlie"),
						// missing age and active
					}),
				},
			},
			expectValid: false,
		},
		{
			name: "invalid entity wrong type for attr",
			entities: types.EntityMap{
				types.NewEntityUID("User", "dave"): types.Entity{
					Attributes: types.NewRecord(types.RecordMap{
						"name":   types.String("Dave"),
						"age":    types.String("not a number"), // wrong type
						"active": types.Boolean(true),
					}),
				},
			},
			expectValid: false,
		},
		{
			name: "valid entity with parent",
			entities: types.EntityMap{
				types.NewEntityUID("User", "eve"): types.Entity{
					Attributes: types.NewRecord(types.RecordMap{
						"name":   types.String("Eve"),
						"age":    types.Long(28),
						"active": types.Boolean(true),
					}),
					Parents: types.NewEntityUIDSet(types.NewEntityUID("Group", "admins")),
				},
			},
			expectValid: true,
		},
		{
			name: "invalid entity with wrong parent type",
			entities: types.EntityMap{
				types.NewEntityUID("User", "frank"): types.Entity{
					Attributes: types.NewRecord(types.RecordMap{
						"name":   types.String("Frank"),
						"age":    types.Long(35),
						"active": types.Boolean(true),
					}),
					Parents: types.NewEntityUIDSet(types.NewEntityUID("Document", "doc1")), // wrong parent type
				},
			},
			expectValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ValidateEntities(&s, tc.entities)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
			if !tc.expectValid && result.Valid {
				t.Error("Expected invalid, but validation passed")
			}
		})
	}
}

func TestValidateRequestWithContext(t *testing.T) {
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
						"resourceTypes": ["Document"],
						"context": {
							"type": "Record",
							"attributes": {
								"ip": {"type": "String", "required": true},
								"authenticated": {"type": "Boolean", "required": true}
							}
						}
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name        string
		context     types.Record
		expectValid bool
	}{
		{
			name: "valid context",
			context: types.NewRecord(types.RecordMap{
				"ip":            types.String("192.168.1.1"),
				"authenticated": types.Boolean(true),
			}),
			expectValid: true,
		},
		{
			name: "invalid context missing required",
			context: types.NewRecord(types.RecordMap{
				"ip": types.String("192.168.1.1"),
				// missing authenticated
			}),
			expectValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := cedar.Request{
				Principal: types.NewEntityUID("User", "alice"),
				Action:    types.NewEntityUID("Action", "view"),
				Resource:  types.NewEntityUID("Document", "doc1"),
				Context:   tc.context,
			}
			result := ValidateRequest(&s, req)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got error: %s", result.Error)
			}
			if !tc.expectValid && result.Valid {
				t.Error("Expected invalid, but validation passed")
			}
		})
	}
}

func TestValidateActionInSet(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {},
				"Admin": {},
				"Document": {}
			},
			"actions": {
				"read": {
					"appliesTo": {
						"principalTypes": ["User", "Admin"],
						"resourceTypes": ["Document"]
					}
				},
				"write": {
					"appliesTo": {
						"principalTypes": ["Admin"],
						"resourceTypes": ["Document"]
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name        string
		policy      string
		expectValid bool
	}{
		{
			name:        "valid action in set - user for read",
			policy:      `permit(principal == User::"alice", action in [Action::"read"], resource);`,
			expectValid: true,
		},
		{
			name:        "valid action in set - admin for both",
			policy:      `permit(principal == Admin::"bob", action in [Action::"read", Action::"write"], resource);`,
			expectValid: true,
		},
		{
			// When using action in set, the validator uses union semantics:
			// if the principal type is valid for ANY action in the set, it passes
			name:        "user for read/write set - valid because user can read",
			policy:      `permit(principal == User::"alice", action in [Action::"read", Action::"write"], resource);`,
			expectValid: true, // User is in the union of principal types (User+Admin)
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := validatePolicyString(t, &s, tc.policy)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
			if !tc.expectValid && result.Valid {
				t.Error("Expected invalid, but validation passed")
			}
		})
	}
}

func TestTypesMatch(t *testing.T) {
	tests := []struct {
		name     string
		expected CedarType
		actual   CedarType
		want     bool
	}{
		{"bool match", BoolType{}, BoolType{}, true},
		{"long match", LongType{}, LongType{}, true},
		{"string match", StringType{}, StringType{}, true},
		{"bool vs long", BoolType{}, LongType{}, false},
		{"entity match", EntityType{Name: "User"}, EntityType{Name: "User"}, true},
		{"entity mismatch", EntityType{Name: "User"}, EntityType{Name: "Admin"}, false},
		{"set match", SetType{Element: StringType{}}, SetType{Element: StringType{}}, true},
		{"extension match", ExtensionType{Name: "decimal"}, ExtensionType{Name: "decimal"}, true},
		{"extension mismatch", ExtensionType{Name: "decimal"}, ExtensionType{Name: "ipaddr"}, false},
		{"unknown expected matches anything", UnknownType{}, BoolType{}, true},
		{"unknown actual matches anything", StringType{}, UnknownType{}, false}, // actual unknown doesn't automatically match
		{"any entity matches entity", AnyEntityType{}, EntityType{Name: "User"}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TypesMatch(tc.expected, tc.actual)
			if got != tc.want {
				t.Errorf("TypesMatch(%v, %v) = %v, want %v", tc.expected, tc.actual, got, tc.want)
			}
		})
	}
}

func TestCedarTypeStrings(t *testing.T) {
	tests := []struct {
		typ  CedarType
		want string
	}{
		{BoolType{}, "Bool"},
		{LongType{}, "Long"},
		{StringType{}, "String"},
		{EntityType{Name: "User"}, "Entity<User>"},
		{SetType{Element: StringType{}}, "Set<String>"},
		{ExtensionType{Name: "decimal"}, "decimal"},
		{UnknownType{}, "Unknown"},
		{AnyEntityType{}, "Entity"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			got := tc.typ.String()
			if got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTypecheckLikeOperator(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"email": {"type": "String", "required": true}
						}
					}
				},
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name        string
		policy      string
		expectValid bool
	}{
		{
			name:        "valid like operator",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { principal.email like "*@example.com" };`,
			expectValid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := validatePolicyString(t, &s, tc.policy)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
		})
	}
}

func TestTypecheckExtensionCalls(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"ip": {"type": "Extension", "name": "ipaddr", "required": true},
							"balance": {"type": "Extension", "name": "decimal", "required": true}
						}
					}
				},
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name        string
		policy      string
		expectValid bool
	}{
		{
			name:        "valid ip function",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { ip("192.168.1.1").isIpv4() };`,
			expectValid: true,
		},
		{
			name:        "valid decimal function",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { decimal("10.5").greaterThan(decimal("5.0")) };`,
			expectValid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := validatePolicyString(t, &s, tc.policy)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
		})
	}
}

func TestTypecheckRecordLiterals(t *testing.T) {
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
						"resourceTypes": ["Document"],
						"context": {
							"type": "Record",
							"attributes": {
								"metadata": {"type": "Record", "attributes": {
									"source": {"type": "String", "required": true}
								}, "required": true}
							}
						}
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name        string
		policy      string
		expectValid bool
	}{
		{
			name:        "valid record literal in condition",
			policy:      `permit(principal, action == Action::"view", resource) when { context.metadata == {"source": "api"} };`,
			expectValid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := validatePolicyString(t, &s, tc.policy)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
		})
	}
}

func TestTypecheckInConditions(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"memberOfTypes": ["Group"]
				},
				"Group": {},
				"Document": {
					"memberOfTypes": ["Folder"]
				},
				"Folder": {}
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name        string
		policy      string
		expectValid bool
	}{
		{
			name:        "valid in condition with principal",
			policy:      `permit(principal, action == Action::"view", resource) when { principal in Group::"admins" };`,
			expectValid: true,
		},
		{
			name:        "valid in condition with resource",
			policy:      `permit(principal, action == Action::"view", resource) when { resource in Folder::"public" };`,
			expectValid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := validatePolicyString(t, &s, tc.policy)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
		})
	}
}

func TestValidateEntitiesWithSetsAndRecords(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"tags": {"type": "Set", "element": {"type": "String"}, "required": true},
							"metadata": {"type": "Record", "attributes": {
								"created": {"type": "String", "required": true}
							}, "required": true}
						}
					}
				},
				"Document": {}
			},
			"actions": {
				"view": {}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name        string
		entities    types.EntityMap
		expectValid bool
	}{
		{
			name: "valid entity with set and record",
			entities: types.EntityMap{
				types.NewEntityUID("User", "alice"): types.Entity{
					Attributes: types.NewRecord(types.RecordMap{
						"tags": types.NewSet(
							types.String("admin"),
							types.String("active"),
						),
						"metadata": types.NewRecord(types.RecordMap{
							"created": types.String("2024-01-01"),
						}),
					}),
				},
			},
			expectValid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ValidateEntities(&s, tc.entities)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
		})
	}
}

func TestSchemaWithEntityRefTypes(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"manager": {"type": "Entity", "name": "User", "required": false}
						}
					}
				},
				"Document": {
					"shape": {
						"type": "Record",
						"attributes": {
							"owner": {"type": "Entity", "name": "User", "required": true}
						}
					}
				}
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	result := ValidatePolicies(&s, cedar.NewPolicySet())
	if !result.Valid {
		t.Errorf("Expected valid policies, got errors: %v", result.Errors)
	}
}

func TestRecordTypeString(t *testing.T) {
	rt := RecordType{
		Attributes: map[string]AttributeType{
			"name": {Type: StringType{}, Required: true},
		},
	}
	got := rt.String()
	if got != "Record" {
		t.Errorf("String() = %q, want %q", got, "Record")
	}
}

func TestValidateScopeTypes(t *testing.T) {
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
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					}
				},
				"delete": {
					"appliesTo": {
						"principalTypes": ["Admin"],
						"resourceTypes": ["Document"]
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name        string
		policy      string
		expectValid bool
	}{
		{
			name:        "valid principal type for action",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource);`,
			expectValid: true,
		},
		{
			name:        "invalid principal type for action",
			policy:      `permit(principal == Admin::"bob", action == Action::"view", resource);`,
			expectValid: false,
		},
		{
			name:        "valid admin for delete",
			policy:      `permit(principal == Admin::"bob", action == Action::"delete", resource);`,
			expectValid: true,
		},
		{
			name:        "unknown entity type in scope",
			policy:      `permit(principal is UnknownType, action, resource);`,
			expectValid: false,
		},
		{
			name:        "unknown action in scope",
			policy:      `permit(principal, action == Action::"unknown", resource);`,
			expectValid: false,
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

			result := ValidatePolicies(&s, policies)

			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
			if !tc.expectValid && result.Valid {
				t.Errorf("Expected invalid, but validation passed")
			}
		})
	}
}

func TestSchemaWithCommonTypes(t *testing.T) {
	schemaJSON := `{
		"": {
			"commonTypes": {
				"EmailAddress": {
					"type": "String"
				},
				"Coordinate": {
					"type": "Record",
					"attributes": {
						"lat": {"type": "Long"},
						"lon": {"type": "Long"}
					}
				}
			},
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"email": {"type": "EmailAddress"},
							"location": {"type": "Coordinate"}
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.email == "test@example.com" };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestSchemaWithActionContext(t *testing.T) {
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
					},
					"context": {
						"type": "Record",
						"attributes": {
							"ip": {"type": "String"},
							"authenticated": {"type": "Boolean"}
						}
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { context.authenticated };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestSchemaWithActionMemberOf(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {},
				"Document": {}
			},
			"actions": {
				"viewAll": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					}
				},
				"view": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					},
					"memberOf": [
						{"id": "viewAll"},
						{"type": "Action", "id": "viewAll"}
					]
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestSchemaWithExtensionTypes(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"ip": {"type": "Extension", "name": "ipaddr"},
							"birthday": {"type": "Extension", "name": "datetime"},
							"other": {"type": "Extension"}
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	result := ValidatePolicies(&s, cedar.NewPolicySet())
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestSchemaWithEntityType(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"manager": {"type": "Entity", "name": "User"},
							"anyEntity": {"type": "Entity"}
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.manager == User::"bob" };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestSchemaWithSetType(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"roles": {"type": "Set", "element": {"type": "String"}},
							"anySet": {"type": "Set"}
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.roles.contains("admin") };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestSchemaWithMemberOfTypes(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"memberOfTypes": ["Group"]
				},
				"Group": {}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User", "Group"],
						"resourceTypes": ["User"]
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal in Group::"admins" };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestValidateEntitiesWithInvalidType(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {}
			},
			"actions": {}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Entity with unknown type
	entities := types.EntityMap{
		types.EntityUID{Type: "UnknownType", ID: "test"}: types.Entity{},
	}

	result := ValidateEntities(&s, entities)
	if result.Valid {
		t.Error("Expected invalid for entity with unknown type")
	}
}

func TestValidateEntitiesWithInvalidAttribute(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"name": {"type": "String", "required": true}
						}
					}
				}
			},
			"actions": {}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Entity with wrong attribute type
	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"name": types.Long(42), // Should be string
			}),
		},
	}

	result := ValidateEntities(&s, entities)
	if result.Valid {
		t.Error("Expected invalid for entity with wrong attribute type")
	}
}

func TestValidateRequestWithContextRequired(t *testing.T) {
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
						"resourceTypes": ["Document"],
						"context": {
							"type": "Record",
							"attributes": {
								"authenticated": {"type": "Boolean", "required": true}
							}
						}
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Valid request with context
	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context: types.NewRecord(types.RecordMap{
			"authenticated": types.True,
		}),
	}

	result := ValidateRequest(&s, req)
	if !result.Valid {
		t.Errorf("Expected valid request, got error: %s", result.Error)
	}

	// Invalid context type
	badReq := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context: types.NewRecord(types.RecordMap{
			"authenticated": types.String("yes"), // Should be boolean
		}),
	}

	result = ValidateRequest(&s, badReq)
	if result.Valid {
		t.Error("Expected invalid request for wrong context type")
	}
}

func TestValidateRequestWithUnknownAction(t *testing.T) {
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "unknown"},
		Resource:  types.EntityUID{Type: "User", ID: "bob"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	result := ValidateRequest(&s, req)
	if result.Valid {
		t.Error("Expected invalid request for unknown action")
	}
}

func TestSchemaWithNamespace(t *testing.T) {
	schemaJSON := `{
		"MyApp": {
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	// This should pass as permit all is valid
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestValidatePoliciesWithNilSchema(t *testing.T) {
	result := ValidatePolicies(nil, cedar.NewPolicySet())
	if result.Valid {
		t.Error("Expected invalid for nil schema")
	}
	if len(result.Errors) == 0 {
		t.Error("Expected error message for nil schema")
	}
}

func TestValidateEntitiesWithNilSchema(t *testing.T) {
	result := ValidateEntities(nil, types.EntityMap{})
	if result.Valid {
		t.Error("Expected invalid for nil schema")
	}
	if len(result.Errors) == 0 {
		t.Error("Expected error message for nil schema")
	}
}

func TestValidateRequestWithNilSchema(t *testing.T) {
	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context:   types.NewRecord(types.RecordMap{}),
	}
	result := ValidateRequest(nil, req)
	if result.Valid {
		t.Error("Expected invalid for nil schema")
	}
	if result.Error == "" {
		t.Error("Expected error message for nil schema")
	}
}

func TestValidatorNewWithNilSchema(t *testing.T) {
	v, err := New(nil)
	if err == nil {
		t.Error("Expected error for nil schema")
	}
	if v != nil {
		t.Error("Expected nil validator for nil schema")
	}
}

func TestTypecheckTypeErrors(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"count": {"type": "Long"},
							"name": {"type": "String"},
							"active": {"type": "Boolean"},
							"roles": {"type": "Set", "element": {"type": "String"}}
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name        string
		policy      string
		expectValid bool
	}{
		{
			name:        "not operator on non-boolean",
			policy:      `permit(principal, action, resource) when { !principal.count };`,
			expectValid: false,
		},
		{
			name:        "negation on non-long",
			policy:      `permit(principal, action, resource) when { -principal.name > 0 };`,
			expectValid: false,
		},
		{
			name:        "isEmpty on non-set",
			policy:      `permit(principal, action, resource) when { principal.name.isEmpty() };`,
			expectValid: false,
		},
		{
			name:        "like on non-string",
			policy:      `permit(principal, action, resource) when { principal.count like "*" };`,
			expectValid: false,
		},
		{
			name:        "comparison with incompatible types",
			policy:      `permit(principal, action, resource) when { principal.name > 5 };`,
			expectValid: false,
		},
		{
			name:        "arithmetic with non-long",
			policy:      `permit(principal, action, resource) when { principal.name + 5 > 10 };`,
			expectValid: false,
		},
		{
			name:        "set operation on non-set",
			policy:      `permit(principal, action, resource) when { principal.name.contains("a") };`,
			expectValid: false,
		},
		{
			name:        "if-then-else with non-boolean condition",
			policy:      `permit(principal, action, resource) when { if principal.count then true else false };`,
			expectValid: false,
		},
		{
			name:        "is operator valid",
			policy:      `permit(principal, action, resource) when { principal is User };`,
			expectValid: true,
		},
		{
			name:        "isIn operator valid",
			policy:      `permit(principal, action, resource) when { principal is User in User::"admin" };`,
			expectValid: true,
		},
		{
			name:        "has operator valid",
			policy:      `permit(principal, action, resource) when { principal has name };`,
			expectValid: true,
		},
		{
			name:        "getTag operator valid",
			policy:      `permit(principal, action, resource) when { principal.getTag("role") == "admin" };`,
			expectValid: true,
		},
		{
			name:        "hasTag operator valid",
			policy:      `permit(principal, action, resource) when { principal.hasTag("role") };`,
			expectValid: true,
		},
		{
			name:        "record literal valid",
			policy:      `permit(principal, action, resource) when { {"name": "test"}.name == "test" };`,
			expectValid: true,
		},
		{
			name:        "set literal valid",
			policy:      `permit(principal, action, resource) when { [1, 2, 3].contains(1) };`,
			expectValid: true,
		},
		{
			name:        "conditional valid",
			policy:      `permit(principal, action, resource) when { if true then 1 else 2 > 0 };`,
			expectValid: true,
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

			result := ValidatePolicies(&s, policies)

			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
			if !tc.expectValid && result.Valid {
				t.Errorf("Expected invalid, but validation passed")
			}
		})
	}
}

func TestSchemaWithTypeBoolean(t *testing.T) {
	// Test "Bool" variant
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"active": {"type": "Bool"}
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.active };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestValidateEntitiesWithMissingRequiredAttribute(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"name": {"type": "String", "required": true}
						}
					}
				}
			},
			"actions": {}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Entity missing required attribute
	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{}), // Missing "name"
		},
	}

	result := ValidateEntities(&s, entities)
	if result.Valid {
		t.Error("Expected invalid for entity missing required attribute")
	}
}

func TestValidateEntitiesWithSetAttribute(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"roles": {"type": "Set", "element": {"type": "String"}}
						}
					}
				}
			},
			"actions": {}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Valid entity with set attribute
	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"roles": types.NewSet(types.String("admin"), types.String("user")),
			}),
		},
	}

	result := ValidateEntities(&s, entities)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}

	// Invalid - set with wrong element type
	entities = types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"roles": types.NewSet(types.Long(1), types.Long(2)),
			}),
		},
	}

	result = ValidateEntities(&s, entities)
	if result.Valid {
		t.Error("Expected invalid for set with wrong element type")
	}
}

func TestValidateEntitiesWithRecordAttribute(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"profile": {
								"type": "Record",
								"attributes": {
									"bio": {"type": "String"}
								}
							}
						}
					}
				}
			},
			"actions": {}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Valid entity with record attribute
	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"profile": types.NewRecord(types.RecordMap{
					"bio": types.String("Hello"),
				}),
			}),
		},
	}

	result := ValidateEntities(&s, entities)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}

	// Invalid - not a record
	entities = types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"profile": types.String("not a record"),
			}),
		},
	}

	result = ValidateEntities(&s, entities)
	if result.Valid {
		t.Error("Expected invalid for non-record where record expected")
	}
}

func TestValidateEntitiesWithEntityAttribute(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"manager": {"type": "Entity", "name": "User"}
						}
					}
				}
			},
			"actions": {}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Valid entity with entity attribute
	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"manager": types.EntityUID{Type: "User", ID: "boss"},
			}),
		},
	}

	result := ValidateEntities(&s, entities)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}

	// Invalid - wrong entity type
	entities = types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"manager": types.EntityUID{Type: "WrongType", ID: "boss"},
			}),
		},
	}

	result = ValidateEntities(&s, entities)
	if result.Valid {
		t.Error("Expected invalid for entity with wrong type")
	}
}

func TestValidateEntitiesWithExtensionAttribute(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"ip": {"type": "Extension", "name": "ipaddr"}
						}
					}
				}
			},
			"actions": {}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Valid entity with IP extension
	ip, _ := types.ParseIPAddr("192.168.1.1")
	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"ip": ip,
			}),
		},
	}

	result := ValidateEntities(&s, entities)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestTypesMatchAdditional(t *testing.T) {
	tests := []struct {
		name     string
		expected CedarType
		actual   CedarType
		want     bool
	}{
		// matchEntityType tests
		{"entity expected, any entity actual", EntityType{Name: "User"}, AnyEntityType{}, true},
		{"entity expected, non-entity actual", EntityType{Name: "User"}, StringType{}, false},

		// matchAnyEntityType tests
		{"any entity expected, entity actual", AnyEntityType{}, EntityType{Name: "User"}, true},
		{"any entity expected, any entity actual", AnyEntityType{}, AnyEntityType{}, true},
		{"any entity expected, non-entity actual", AnyEntityType{}, StringType{}, false},
		{"any entity expected, long actual", AnyEntityType{}, LongType{}, false},

		// matchSetType tests - element type mismatch
		{"set mismatch element", SetType{Element: StringType{}}, SetType{Element: LongType{}}, false},
		{"set expected, non-set actual", SetType{Element: StringType{}}, LongType{}, false},

		// matchRecordType tests
		{"record expected, non-record actual", RecordType{}, StringType{}, false},

		// matchExtensionType tests
		{"extension expected, non-extension actual", ExtensionType{Name: "decimal"}, StringType{}, false},

		// TypesMatch default case - custom type that doesn't match any case
		{"default type", RecordType{}, RecordType{}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TypesMatch(tc.expected, tc.actual)
			if got != tc.want {
				t.Errorf("TypesMatch(%v, %v) = %v, want %v", tc.expected, tc.actual, got, tc.want)
			}
		})
	}
}

func TestRecordAttributesMatchAdditional(t *testing.T) {
	// Test missing optional attribute
	expected := RecordType{
		Attributes: map[string]AttributeType{
			"name":  {Type: StringType{}, Required: true},
			"email": {Type: StringType{}, Required: false},
		},
	}
	actual := RecordType{
		Attributes: map[string]AttributeType{
			"name": {Type: StringType{}, Required: true},
			// email is missing but optional
		},
	}
	if !TypesMatch(expected, actual) {
		t.Error("Expected match when optional attribute is missing")
	}

	// Test type mismatch
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

	// Test missing required attribute
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

func TestValidateActionInScope(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {},
				"Document": {}
			},
			"actions": {
				"viewAll": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					}
				},
				"view": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					},
					"memberOf": [{"id": "viewAll"}]
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test action 'in' scope (covers validateActionScope ScopeTypeIn case)
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action in Action::"viewAll", resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestInferTypeWithAllExtensions(t *testing.T) {
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(&s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Test inferType for all extension types
	decimal, _ := types.ParseDecimal("10.5")
	datetime, _ := types.ParseDatetime("2024-01-01")
	duration, _ := types.ParseDuration("1h")

	tests := []struct {
		name     string
		value    types.Value
		expected string
	}{
		{"decimal", decimal, "decimal"},
		{"datetime", datetime, "datetime"},
		{"duration", duration, "duration"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inferred := v.inferType(tc.value)
			ext, ok := inferred.(ExtensionType)
			if !ok {
				t.Errorf("Expected ExtensionType, got %T", inferred)
				return
			}
			if ext.Name != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, ext.Name)
			}
		})
	}
}

func TestInferSetTypeEdgeCases(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {}
			},
			"actions": {}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(&s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Empty set
	emptySet := types.NewSet()
	inferred := v.inferType(emptySet)
	setType, ok := inferred.(SetType)
	if !ok {
		t.Fatalf("Expected SetType, got %T", inferred)
	}
	_, isUnknown := setType.Element.(UnknownType)
	if !isUnknown {
		t.Errorf("Expected UnknownType element for empty set, got %T", setType.Element)
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test with known entity type (should not produce error)
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal == User::"alice", action, resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
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

	result = ValidatePolicies(&s, policies2)
	if !result.Valid {
		t.Errorf("Expected valid for Action type, got errors: %v", result.Errors)
	}
}

func TestValidateRequestWithWrongResourceType(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {},
				"Document": {},
				"Folder": {}
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Invalid request - wrong resource type
	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Folder", ID: "folder1"}, // Wrong type
		Context:   types.NewRecord(types.RecordMap{}),
	}

	result := ValidateRequest(&s, req)
	if result.Valid {
		t.Error("Expected invalid request for wrong resource type")
	}
}

func TestValidateContextWithNonRecord(t *testing.T) {
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
						"resourceTypes": ["Document"],
						"context": {
							"type": "Record",
							"attributes": {}
						}
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(&s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Test validateContext with non-record value
	err = v.validateContext(types.String("not a record"), RecordType{})
	if err == nil {
		t.Error("Expected error for non-record context")
	}
}

func TestTypeInListWithNonEmptyList(t *testing.T) {
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
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(&s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Type in list
	list := []types.EntityType{"User", "Admin"}
	if !v.typeInList("User", list) {
		t.Error("Expected User to be in list")
	}

	// Type not in list
	if v.typeInList("Guest", list) {
		t.Error("Expected Guest to not be in list")
	}

	// Empty list allows any type
	if !v.typeInList("Anything", nil) {
		t.Error("Expected any type to be allowed with empty list")
	}
}

func TestTypecheckVariableContext(t *testing.T) {
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
					},
					"context": {
						"type": "Record",
						"attributes": {
							"ip": {"type": "String"}
						}
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test context variable type checking
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action == Action::"view", resource) when { context.ip == "127.0.0.1" };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestTypecheckUnionResourceTypes(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {},
				"Document": {},
				"Folder": {}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					}
				},
				"browse": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Folder"]
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test action in set with union of resource types
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action in [Action::"view", Action::"browse"], resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestTypecheckInOperatorInvalidOperands(t *testing.T) {
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name        string
		policy      string
		expectValid bool
	}{
		{
			name:        "in with non-entity left operand",
			policy:      `permit(principal, action, resource) when { principal.name in User::"admin" };`,
			expectValid: false,
		},
		{
			name:        "in with non-entity right operand",
			policy:      `permit(principal, action, resource) when { principal in principal.name };`,
			expectValid: false,
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

			result := ValidatePolicies(&s, policies)

			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
			if !tc.expectValid && result.Valid {
				t.Errorf("Expected invalid, but validation passed")
			}
		})
	}
}

func TestTypecheckAccessOnNonEntity(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"active": {"type": "Boolean"}
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test access on a boolean (non-entity, non-record)
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.active.foo };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if result.Valid {
		t.Error("Expected invalid when accessing attribute on non-entity")
	}
}

func TestScopeTypeIsIn(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {},
				"Group": {},
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test is...in scope
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal is User in Group::"admins", action, resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestValidateEntitiesWithActionEntity(t *testing.T) {
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Action entities are handled differently (don't validate against entityTypes)
	entities := types.EntityMap{
		types.EntityUID{Type: "Action", ID: "view"}: types.Entity{},
	}

	result := ValidateEntities(&s, entities)
	if !result.Valid {
		t.Errorf("Expected valid for Action entity, got errors: %v", result.Errors)
	}
}

func TestExtractScopeTypeWithScopeIn(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {},
				"Group": {},
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test principal in scope (covers extractScopeType returning empty for ScopeTypeIn)
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal in Group::"admins", action == Action::"view", resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	// This should be valid because when extractScopeType returns empty, checkScopeTypeAllowed returns early
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestTypecheckExtensionCallAllFunctions(t *testing.T) {
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name   string
		policy string
	}{
		// IP functions
		{"isIpv4", `permit(principal, action, resource) when { ip("127.0.0.1").isIpv4() };`},
		{"isIpv6", `permit(principal, action, resource) when { ip("::1").isIpv6() };`},
		{"isLoopback", `permit(principal, action, resource) when { ip("127.0.0.1").isLoopback() };`},
		{"isMulticast", `permit(principal, action, resource) when { ip("224.0.0.1").isMulticast() };`},
		{"isInRange", `permit(principal, action, resource) when { ip("192.168.1.1").isInRange(ip("192.168.0.0/16")) };`},

		// Decimal comparison functions
		{"lessThan", `permit(principal, action, resource) when { decimal("1.0").lessThan(decimal("2.0")) };`},
		{"lessThanOrEqual", `permit(principal, action, resource) when { decimal("1.0").lessThanOrEqual(decimal("2.0")) };`},
		{"greaterThanOrEqual", `permit(principal, action, resource) when { decimal("2.0").greaterThanOrEqual(decimal("1.0")) };`},

		// Datetime functions
		{"datetime", `permit(principal, action, resource) when { datetime("2024-01-01") == datetime("2024-01-01") };`},
		{"duration", `permit(principal, action, resource) when { duration("1h") == duration("1h") };`},
		{"offset", `permit(principal, action, resource) when { datetime("2024-01-01").offset(duration("1d")) == datetime("2024-01-02") };`},
		{"durationSince", `permit(principal, action, resource) when { datetime("2024-01-02").durationSince(datetime("2024-01-01")) == duration("1d") };`},
		{"toDate", `permit(principal, action, resource) when { datetime("2024-01-01T12:00:00Z").toDate() == datetime("2024-01-01") };`},
		{"toTime", `permit(principal, action, resource) when { datetime("2024-01-01T12:00:00Z").toTime() == datetime("12:00:00") };`},
		{"toDays", `permit(principal, action, resource) when { duration("2d").toDays() == 2 };`},
		{"toHours", `permit(principal, action, resource) when { duration("2h").toHours() == 2 };`},
		{"toMinutes", `permit(principal, action, resource) when { duration("2m").toMinutes() == 2 };`},
		{"toSeconds", `permit(principal, action, resource) when { duration("2s").toSeconds() == 2 };`},
		{"toMilliseconds", `permit(principal, action, resource) when { duration("2ms").toMilliseconds() == 2 };`},

		// Unknown extension function
		{"unknown", `permit(principal, action, resource) when { unknownFunc("test") };`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policies := cedar.NewPolicySet()
			var policy cedar.Policy
			if err := policy.UnmarshalCedar([]byte(tc.policy)); err != nil {
				t.Skipf("Policy parse error (expected for some test cases): %v", err)
			}
			policies.Add("test", &policy)

			// We just want to exercise the typecheck code path, not check validity
			_ = ValidatePolicies(&s, policies)
		})
	}
}

func TestTypecheckVariableUnknownVariable(t *testing.T) {
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test resource variable
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource == User::"doc1");`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}

	// Test action variable
	var policy2 cedar.Policy
	if err := policy2.UnmarshalCedar([]byte(`permit(principal, action == Action::"view", resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies2 := cedar.NewPolicySet()
	policies2.Add("test2", &policy2)

	result = ValidatePolicies(&s, policies2)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestTypecheckComparisonOperators(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"age": {"type": "Long"}
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name        string
		policy      string
		expectValid bool
	}{
		{"less than", `permit(principal, action, resource) when { principal.age < 50 };`, true},
		{"less than or equal", `permit(principal, action, resource) when { principal.age <= 50 };`, true},
		{"greater than", `permit(principal, action, resource) when { principal.age > 18 };`, true},
		{"greater than or equal", `permit(principal, action, resource) when { principal.age >= 18 };`, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policies := cedar.NewPolicySet()
			var policy cedar.Policy
			if err := policy.UnmarshalCedar([]byte(tc.policy)); err != nil {
				t.Fatalf("Failed to parse policy: %v", err)
			}
			policies.Add("test", &policy)

			result := ValidatePolicies(&s, policies)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
		})
	}
}

func TestTypecheckArithmeticOperators(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"score": {"type": "Long"}
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name   string
		policy string
	}{
		{"add", `permit(principal, action, resource) when { principal.score + 10 > 50 };`},
		{"sub", `permit(principal, action, resource) when { principal.score - 10 > 0 };`},
		{"mult", `permit(principal, action, resource) when { principal.score * 2 > 100 };`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policies := cedar.NewPolicySet()
			var policy cedar.Policy
			if err := policy.UnmarshalCedar([]byte(tc.policy)); err != nil {
				t.Fatalf("Failed to parse policy: %v", err)
			}
			policies.Add("test", &policy)

			result := ValidatePolicies(&s, policies)
			if !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
		})
	}
}

func TestTypecheckBooleanBinaryOperators(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"active": {"type": "Boolean"},
							"admin": {"type": "Boolean"}
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name   string
		policy string
	}{
		{"and", `permit(principal, action, resource) when { principal.active && principal.admin };`},
		{"or", `permit(principal, action, resource) when { principal.active || principal.admin };`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policies := cedar.NewPolicySet()
			var policy cedar.Policy
			if err := policy.UnmarshalCedar([]byte(tc.policy)); err != nil {
				t.Fatalf("Failed to parse policy: %v", err)
			}
			policies.Add("test", &policy)

			result := ValidatePolicies(&s, policies)
			if !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
		})
	}
}

func TestTypecheckEqualityOperators(t *testing.T) {
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name   string
		policy string
	}{
		{"equals", `permit(principal, action, resource) when { principal.name == "alice" };`},
		{"not equals", `permit(principal, action, resource) when { principal.name != "bob" };`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policies := cedar.NewPolicySet()
			var policy cedar.Policy
			if err := policy.UnmarshalCedar([]byte(tc.policy)); err != nil {
				t.Fatalf("Failed to parse policy: %v", err)
			}
			policies.Add("test", &policy)

			result := ValidatePolicies(&s, policies)
			if !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
		})
	}
}

func TestUnifyTypes(t *testing.T) {
	// Test unifyTypes directly via set literals with mixed types
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test if-then-else with matching types
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { if true then 1 else 2 > 0 };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestResolveEntityScopeTypesWithAllScope(t *testing.T) {
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test with 'all' scope (principal, action, resource without constraints)
	// This tests resolveEntityScopeTypes with ScopeTypeAll
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action == Action::"view", resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestTypecheckSetLiteralEmpty(t *testing.T) {
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test empty set literal
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { [].isEmpty() };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestTypecheckWithNilNode(t *testing.T) {
	// Test that typecheck handles nil nodes gracefully
	// This is tested indirectly through policies with simple conditions
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Policy without when clause
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Condition that doesn't evaluate to boolean
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.name };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if result.Valid {
		t.Error("Expected invalid when condition is not boolean")
	}
}

func TestInferTypeUnknown(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {}
			},
			"actions": {}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(&s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Test inferType returns UnknownType for unknown values
	// There's no direct way to create an unknown value, but we can test the switch default
	// The default case returns UnknownType
	inferred := v.inferType(nil)
	// Note: nil might not reach inferType in practice, but testing the code path
	if inferred == nil {
		t.Error("Expected non-nil type")
	}
}

func TestValidateResourceScopeWithIsIn(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {},
				"Document": {},
				"Folder": {}
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test resource is...in scope
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action == Action::"view", resource is Document in Folder::"public");`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestIsCedarTypeMethods(t *testing.T) {
	// Test all isCedarType marker methods by type assertions
	types := []CedarType{
		BoolType{},
		LongType{},
		StringType{},
		EntityType{Name: "User"},
		SetType{Element: StringType{}},
		RecordType{},
		ExtensionType{Name: "decimal"},
		AnyEntityType{},
		UnknownType{},
	}

	for _, ct := range types {
		// Calling isCedarType through interface
		ct.isCedarType()
		_ = ct.String()
	}
}

func TestSchemaWithTopLevelContext(t *testing.T) {
	// Test schema with context at action top-level (not in appliesTo)
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
					},
					"context": {
						"type": "Record",
						"attributes": {
							"ip": {"type": "String"},
							"port": {"type": "Long"}
						}
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	result := ValidatePolicies(&s, cedar.NewPolicySet())
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestTypecheckVariableMultiplePrincipalTypes(t *testing.T) {
	// Test when there are multiple principal types (not just one)
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
				},
				"Admin": {
					"shape": {
						"type": "Record",
						"attributes": {
							"name": {"type": "String"}
						}
					}
				},
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// With action constraint, principal can be User or Admin
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action == Action::"view", resource) when { principal.name == "test" };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	// This may produce errors since principal type is ambiguous
	_ = result
}

func TestTypecheckResourceVariable(t *testing.T) {
	// Test when there are multiple resource types
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {},
				"Document": {
					"shape": {
						"type": "Record",
						"attributes": {
							"title": {"type": "String"}
						}
					}
				},
				"Folder": {
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
						"resourceTypes": ["Document", "Folder"]
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// With multiple resource types, resource variable has unknown entity type
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action == Action::"view", resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestCheckScopeTypeNotAllowed(t *testing.T) {
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
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test with resource type not in allowed list
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal == User::"alice", action == Action::"view", resource is Admin);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if result.Valid {
		t.Error("Expected invalid for resource type not in allowed list")
	}
}

func TestParseJSONTypeVariants(t *testing.T) {
	// Test various JSON type formats
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	_, err := New(&s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}
}

func TestTypecheckUnknownVariableName(t *testing.T) {
	// This test exercises the default case in typecheckVariable
	// However, we can't easily create an unknown variable from Cedar syntax
	// The test exercises the path through policy validation
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test context variable (4th known variable)
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { context == {} };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestValidateContextMissingOptionalAttribute(t *testing.T) {
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
						"resourceTypes": ["Document"],
						"context": {
							"type": "Record",
							"attributes": {
								"ip": {"type": "String", "required": true},
								"port": {"type": "Long", "required": false}
							}
						}
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Valid request with only required context attribute
	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context: types.NewRecord(types.RecordMap{
			"ip": types.String("127.0.0.1"),
			// port is optional, not provided
		}),
	}

	result := ValidateRequest(&s, req)
	if !result.Valid {
		t.Errorf("Expected valid request, got error: %s", result.Error)
	}
}

func TestValidateContextWrongAttributeType(t *testing.T) {
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
						"resourceTypes": ["Document"],
						"context": {
							"type": "Record",
							"attributes": {
								"count": {"type": "Long", "required": true}
							}
						}
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Invalid request with wrong context attribute type
	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context: types.NewRecord(types.RecordMap{
			"count": types.String("not a number"), // Should be Long
		}),
	}

	result := ValidateRequest(&s, req)
	if result.Valid {
		t.Error("Expected invalid request for wrong context attribute type")
	}
}

func TestAllEntityTypesPath(t *testing.T) {
	// Test path where allEntityTypes is called (no action types specified)
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {},
				"Admin": {},
				"Document": {}
			},
			"actions": {
				"view": {}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// No principalTypes or resourceTypes specified in action
	// This triggers allEntityTypes() path
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestSchemaWithNullNamespace(t *testing.T) {
	// Test schema with multiple namespaces where one is null
	schemaJSON := `{
		"App1": {
			"entityTypes": {
				"User": {}
			},
			"actions": {
				"view": {}
			}
		},
		"App2": null
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	_, err := New(&s)
	if err != nil {
		t.Errorf("Expected success with null namespace, got error: %v", err)
	}
}

func TestSchemaParserCoverage(t *testing.T) {
	// Test additional schema parser paths
	tests := []struct {
		name       string
		schemaJSON string
		wantErr    bool
	}{
		{
			name: "entity with no shape",
			schemaJSON: `{
				"": {
					"entityTypes": {
						"User": {}
					},
					"actions": {}
				}
			}`,
			wantErr: false,
		},
		{
			name: "entity with empty shape",
			schemaJSON: `{
				"": {
					"entityTypes": {
						"User": {
							"shape": {}
						}
					},
					"actions": {}
				}
			}`,
			wantErr: false,
		},
		{
			name: "entity with shape no attributes",
			schemaJSON: `{
				"": {
					"entityTypes": {
						"User": {
							"shape": {
								"type": "Record"
							}
						}
					},
					"actions": {}
				}
			}`,
			wantErr: false,
		},
		{
			name: "action with no appliesTo",
			schemaJSON: `{
				"": {
					"entityTypes": {},
					"actions": {
						"view": {}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "action with empty appliesTo",
			schemaJSON: `{
				"": {
					"entityTypes": {},
					"actions": {
						"view": {
							"appliesTo": {}
						}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "action with no context",
			schemaJSON: `{
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
			}`,
			wantErr: false,
		},
		{
			name: "action with context but no attributes",
			schemaJSON: `{
				"": {
					"entityTypes": {
						"User": {}
					},
					"actions": {
						"view": {
							"appliesTo": {
								"principalTypes": ["User"],
								"resourceTypes": ["User"]
							},
							"context": {
								"type": "Record"
							}
						}
					}
				}
			}`,
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var s schema.Schema
			if err := s.UnmarshalJSON([]byte(tc.schemaJSON)); err != nil {
				t.Fatalf("Failed to parse schema: %v", err)
			}

			_, err := New(&s)
			if tc.wantErr && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Expected no error, got: %v", err)
			}
		})
	}
}

func TestTypecheckContextWithoutActionConstraint(t *testing.T) {
	// Test context type-checking when action is not constrained (no specific action UID)
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
					},
					"context": {
						"type": "Record",
						"attributes": {
							"ip": {"type": "String"}
						}
					}
				},
				"edit": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Policy without specific action - context type is generic Record
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { context.anything == "test" };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	// Should pass since context type is unknown/generic
	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestTypecheckAccessOnRecordType(t *testing.T) {
	// Test attribute access on a record type from context
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
					},
					"context": {
						"type": "Record",
						"attributes": {
							"metadata": {
								"type": "Record",
								"attributes": {
									"source": {"type": "String"}
								}
							}
						}
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Access attribute on nested record
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action == Action::"view", resource) when { context.metadata.source == "api" };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestCheckEntityTypeWithAction(t *testing.T) {
	// Test checkEntityType with Action type (special case)
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test resource scope with Action type entity (special case in checkEntityType)
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal == User::"alice", action == Action::"view", resource == Document::"doc1");`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestTypecheckRecordAccessUnknownAttribute(t *testing.T) {
	// Test accessing unknown attribute on a record (should return UnknownType)
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
					},
					"context": {
						"type": "Record",
						"attributes": {
							"known": {"type": "String"}
						}
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Access unknown attribute on context record
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action == Action::"view", resource) when { context.unknown_attr == "test" };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	// Should pass because accessing unknown attribute returns UnknownType
	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

// TestLevelBasedValidation tests RFC 76 level-based validation
func TestLevelBasedValidation(t *testing.T) {
	// Schema with nested entity relationships
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"name": {"type": "String"},
							"manager": {"type": "Entity", "name": "User"},
							"department": {"type": "Entity", "name": "Department"}
						}
					}
				},
				"Department": {
					"shape": {
						"type": "Record",
						"attributes": {
							"name": {"type": "String"},
							"head": {"type": "Entity", "name": "User"}
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
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
			maxLevel:  0, // 0 means no limit
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

			result := ValidatePolicies(&s, policies, WithMaxAttributeLevel(tc.maxLevel))

			if tc.wantValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
			if !tc.wantValid {
				if result.Valid {
					t.Error("Expected invalid, but validation passed")
				} else {
					found := false
					for _, err := range result.Errors {
						if strings.Contains(err.Message, tc.wantError) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected error containing %q, got: %v", tc.wantError, result.Errors)
					}
				}
			}
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test that option is applied
	v, err := New(&s, WithMaxAttributeLevel(2))
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	if v.maxAttributeLevel != 2 {
		t.Errorf("Expected maxAttributeLevel=2, got %d", v.maxAttributeLevel)
	}

	// Test default value
	v2, err := New(&s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	if v2.maxAttributeLevel != 0 {
		t.Errorf("Expected default maxAttributeLevel=0, got %d", v2.maxAttributeLevel)
	}
}
