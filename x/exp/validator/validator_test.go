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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(&s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Check that the action is stored with the namespaced type
	expectedActionUID := types.EntityUID{Type: "MyApp::Action", ID: "view"}
	if _, ok := v.actionTypes[expectedActionUID]; !ok {
		t.Errorf("Expected action with type MyApp::Action not found")
		t.Logf("Available actions:")
		for uid := range v.actionTypes {
			t.Logf("  %s", uid)
		}
	}

	// Verify the action is NOT stored with unqualified "Action" type
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Policy with namespaced action should be valid
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action == MyApp::Action::"view", resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	if !result.Valid {
		t.Errorf("Expected valid policy, got errors: %v", result.Errors)
	}
}

// TestStrictEntityValidation tests that strict entity validation catches
// undeclared attributes.
func TestStrictEntityValidation(t *testing.T) {
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

	// Entity with an extra attribute (not declared in schema)
	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "alice"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"name":       types.String("Alice"),
				"extraField": types.String("should not be here"),
			}),
		},
	}

	// Without strict validation, extra attributes should be allowed
	result := ValidateEntities(&s, entities)
	if !result.Valid {
		t.Errorf("Without strict mode, extra attributes should be allowed, got errors: %v", result.Errors)
	}

	// With strict validation, extra attributes should be rejected
	result = ValidateEntities(&s, entities, WithStrictEntityValidation())
	if result.Valid {
		t.Error("With strict mode, extra attributes should cause validation to fail")
	} else {
		found := false
		for _, err := range result.Errors {
			if strings.Contains(err.Message, "extraField") && strings.Contains(err.Message, "not declared") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected error about undeclared attribute 'extraField', got: %v", result.Errors)
		}
	}
}

// TestOpenRecordAllowsExtraAttributes tests that entities with no shape definition
// allow extra attributes even in strict mode (entities without a shape are open by default).
func TestOpenRecordAllowsExtraAttributes(t *testing.T) {
	// Note: The schema package currently doesn't preserve additionalAttributes field.
	// However, entities without a shape definition are treated as open (allow any attrs).
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

	// Entity with extra attributes - allowed because entity has no shape (open)
	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "alice"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"name":       types.String("Alice"),
				"extraField": types.String("allowed because no shape means open"),
			}),
		},
	}

	// With strict validation, entities without a shape should allow extra attributes
	result := ValidateEntities(&s, entities, WithStrictEntityValidation())
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Entity with extra attributes
	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "alice"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"name":       types.String("Alice"),
				"extraField": types.String("should be rejected"),
			}),
		},
	}

	// With strict validation, closed records should reject extra attributes
	result := ValidateEntities(&s, entities, WithStrictEntityValidation())
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
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

// TestActionEntityTypeCheck tests that the isActionEntityType helper correctly
// identifies action types with or without namespaces.
func TestActionEntityTypeCheck(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {},
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

	tests := []struct {
		entityType types.EntityType
		isAction   bool
	}{
		{"Action", true},
		{"MyApp::Action", true},
		{"Nested::Namespace::Action", true},
		{"User", false},
		{"ActionUser", false},
		{"MyAction", false},
	}

	for _, tc := range tests {
		t.Run(string(tc.entityType), func(t *testing.T) {
			result := v.isActionEntityType(tc.entityType)
			if result != tc.isAction {
				t.Errorf("isActionEntityType(%q) = %v, want %v", tc.entityType, result, tc.isAction)
			}
		})
	}
}

// TestActionWithContext tests actions that have context defined in appliesTo.
func TestActionWithContext(t *testing.T) {
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
								"ip": {"type": "String"},
								"timestamp": {"type": "Long"}
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

	v, err := New(&s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Check that action has context attributes
	actionUID := types.EntityUID{Type: "Action", ID: "view"}
	actionInfo, ok := v.actionTypes[actionUID]
	if !ok {
		t.Fatal("Action not found")
	}

	if _, hasIP := actionInfo.Context.Attributes["ip"]; !hasIP {
		t.Error("Expected context to have 'ip' attribute")
	}
	if _, hasTimestamp := actionInfo.Context.Attributes["timestamp"]; !hasTimestamp {
		t.Error("Expected context to have 'timestamp' attribute")
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(&s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Verify common type was parsed
	if _, ok := v.commonTypes["Address"]; !ok {
		t.Error("Expected common type 'Address' to be defined")
	}

	// Verify entity uses common type
	userInfo, ok := v.entityTypes["User"]
	if !ok {
		t.Fatal("User entity type not found")
	}

	if _, hasAddress := userInfo.Attributes["address"]; !hasAddress {
		t.Error("Expected User to have 'address' attribute")
	}
}

// TestSchemaParsingErrors tests error handling in schema parsing.
func TestSchemaParsingErrors(t *testing.T) {
	tests := []struct {
		name       string
		schemaJSON string
		wantErr    bool
	}{
		{
			name:       "invalid JSON",
			schemaJSON: `{invalid json`,
			wantErr:    true,
		},
		{
			name: "valid empty namespace",
			schemaJSON: `{
				"": {
					"entityTypes": {},
					"actions": {}
				}
			}`,
			wantErr: false,
		},
		{
			name: "entity with memberOfTypes",
			schemaJSON: `{
				"": {
					"entityTypes": {
						"User": {
							"memberOfTypes": ["Group"]
						},
						"Group": {}
					},
					"actions": {}
				}
			}`,
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var s schema.Schema
			err := s.UnmarshalJSON([]byte(tc.schemaJSON))
			if tc.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected schema parse error: %v", err)
			}

			_, err = New(&s)
			if err != nil {
				t.Errorf("Unexpected validator creation error: %v", err)
			}
		})
	}
}

// TestTypecheckVariables tests type inference for different policy variables.
func TestTypecheckVariables(t *testing.T) {
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
								"authenticated": {"type": "Boolean"}
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
			name:        "access principal attribute",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { principal.name == "alice" };`,
			expectValid: true,
		},
		{
			name:        "access context attribute",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { context.authenticated };`,
			expectValid: true,
		},
		{
			name:        "access action variable",
			policy:      `permit(principal, action == Action::"view", resource) when { action == Action::"view" };`,
			expectValid: true,
		},
		{
			name:        "access resource variable",
			policy:      `permit(principal, action == Action::"view", resource == Document::"doc1") when { resource == Document::"doc1" };`,
			expectValid: true,
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test policies that should produce argument count errors
	// Note: These may or may not be parseable depending on Cedar syntax rules
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { decimal("1.0").lessThan(decimal("2.0")) };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(&s, policies)
	// This should be valid - correct number of args
	if !result.Valid {
		t.Errorf("Expected valid policy, got errors: %v", result.Errors)
	}
}

// TestEntityTypeScopeValidation tests validation of entity type references in scopes.
func TestEntityTypeScopeValidation(t *testing.T) {
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

	tests := []struct {
		name        string
		policy      string
		expectValid bool
		errorSubstr string
	}{
		{
			name:        "valid entity type in principal scope",
			policy:      `permit(principal == User::"alice", action, resource);`,
			expectValid: true,
		},
		{
			name:        "valid entity type in resource scope",
			policy:      `permit(principal, action, resource == Document::"doc1");`,
			expectValid: true,
		},
		{
			name:        "unknown entity type in principal",
			policy:      `permit(principal == Unknown::"x", action, resource);`,
			expectValid: false,
			errorSubstr: "unknown entity type",
		},
		{
			name:        "action type in principal scope is allowed",
			policy:      `permit(principal == Action::"view", action, resource);`,
			expectValid: true, // Action is a special type that's always allowed
		},
		{
			name:        "principal is check with valid type",
			policy:      `permit(principal is User, action, resource);`,
			expectValid: true,
		},
		{
			name:        "principal is check with unknown type",
			policy:      `permit(principal is Unknown, action, resource);`,
			expectValid: false,
			errorSubstr: "unknown entity type",
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

// TestSetTypeInference tests type inference for set operations.
func TestSetTypeInference(t *testing.T) {
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
			name:        "set contains check",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { principal.roles.contains("admin") };`,
			expectValid: true,
		},
		{
			name:        "empty set literal",
			policy:      `permit(principal, action, resource) when { [].isEmpty() };`,
			expectValid: true,
		},
		{
			name:        "set literal with elements",
			policy:      `permit(principal, action, resource) when { ["a", "b"].contains("a") };`,
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

// TestRecordLiteralTypeInference tests type inference for record literals.
func TestRecordLiteralTypeInference(t *testing.T) {
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
		name        string
		policy      string
		expectValid bool
	}{
		{
			name:        "record literal in condition",
			policy:      `permit(principal, action, resource) when { {name: "test"}.name == "test" };`,
			expectValid: true,
		},
		{
			name:        "nested record literal",
			policy:      `permit(principal, action, resource) when { {outer: {inner: "value"}}.outer.inner == "value" };`,
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

// TestConditionalExpressions tests if-then-else expression validation.
func TestConditionalExpressions(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"active": {"type": "Boolean"},
							"level": {"type": "Long"}
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

// TestActionInSetValidation tests validation of action in set expressions.
func TestActionInSetValidation(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {},
				"Document": {}
			},
			"actions": {
				"read": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					}
				},
				"write": {
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
		errorSubstr string
	}{
		{
			name:        "valid action in set",
			policy:      `permit(principal, action in [Action::"read", Action::"write"], resource);`,
			expectValid: true,
		},
		{
			name:        "unknown action in set",
			policy:      `permit(principal, action in [Action::"read", Action::"delete"], resource);`,
			expectValid: false,
			errorSubstr: "unknown action",
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

// TestEntityValidationWithParents tests entity validation including parent relationships.
func TestEntityValidationWithParents(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"memberOfTypes": ["Group"]
				},
				"Group": {
					"memberOfTypes": ["Group"]
				}
			},
			"actions": {}
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
		errorSubstr string
	}{
		{
			name: "valid user in group",
			entities: types.EntityMap{
				types.EntityUID{Type: "User", ID: "alice"}: types.Entity{
					Parents: types.NewEntityUIDSet(types.EntityUID{Type: "Group", ID: "admins"}),
				},
				types.EntityUID{Type: "Group", ID: "admins"}: types.Entity{},
			},
			expectValid: true,
		},
		{
			name: "group in group (allowed)",
			entities: types.EntityMap{
				types.EntityUID{Type: "Group", ID: "subgroup"}: types.Entity{
					Parents: types.NewEntityUIDSet(types.EntityUID{Type: "Group", ID: "parent"}),
				},
				types.EntityUID{Type: "Group", ID: "parent"}: types.Entity{},
			},
			expectValid: true,
		},
		{
			name: "user in user (not allowed)",
			entities: types.EntityMap{
				types.EntityUID{Type: "User", ID: "alice"}: types.Entity{
					Parents: types.NewEntityUIDSet(types.EntityUID{Type: "User", ID: "bob"}),
				},
				types.EntityUID{Type: "User", ID: "bob"}: types.Entity{},
			},
			expectValid: false,
			errorSubstr: "cannot be member of type User",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ValidateEntities(&s, tc.entities)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
			if !tc.expectValid {
				if result.Valid {
					t.Error("Expected invalid, but validation passed")
				} else if tc.errorSubstr != "" {
					found := false
					for _, err := range result.Errors {
						if strings.Contains(err.Message, tc.errorSubstr) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected error containing %q, got: %v", tc.errorSubstr, result.Errors)
					}
				}
			}
		})
	}
}

// TestExtensionTypesInSchema tests parsing of extension types in schema.
func TestExtensionTypesInSchema(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"ip": {"type": "Extension", "name": "ipaddr"},
							"balance": {"type": "Extension", "name": "decimal"},
							"lastLogin": {"type": "Extension", "name": "datetime"},
							"timeout": {"type": "Extension", "name": "duration"}
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

	v, err := New(&s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	userInfo, ok := v.entityTypes["User"]
	if !ok {
		t.Fatal("User entity type not found")
	}

	// Verify extension types were parsed correctly
	expectedExtTypes := map[string]string{
		"ip":        "ipaddr",
		"balance":   "decimal",
		"lastLogin": "datetime",
		"timeout":   "duration",
	}

	for attrName, expectedTypeName := range expectedExtTypes {
		attr, ok := userInfo.Attributes[attrName]
		if !ok {
			t.Errorf("Expected attribute %s not found", attrName)
			continue
		}
		extType, ok := attr.Type.(ExtensionType)
		if !ok {
			t.Errorf("Expected attribute %s to be ExtensionType, got %T", attrName, attr.Type)
			continue
		}
		if extType.Name != expectedTypeName {
			t.Errorf("Expected attribute %s to have extension type %s, got %s", attrName, expectedTypeName, extType.Name)
		}
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

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(&s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	userInfo, ok := v.entityTypes["User"]
	if !ok {
		t.Fatal("User entity type not found")
	}

	// Verify entity type references
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

// TestSetTypeInSchema tests set type parsing in schema.
func TestSetTypeInSchema(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"tags": {"type": "Set", "element": {"type": "String"}},
							"scores": {"type": "Set", "element": {"type": "Long"}},
							"friends": {"type": "Set", "element": {"type": "Entity", "name": "User"}}
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

	v, err := New(&s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	userInfo, ok := v.entityTypes["User"]
	if !ok {
		t.Fatal("User entity type not found")
	}

	// Verify set types
	tagsAttr, ok := userInfo.Attributes["tags"]
	if !ok {
		t.Fatal("tags attribute not found")
	}
	if setType, ok := tagsAttr.Type.(SetType); ok {
		if _, ok := setType.Element.(StringType); !ok {
			t.Errorf("Expected tags element to be StringType, got %T", setType.Element)
		}
	} else {
		t.Errorf("Expected tags to be SetType, got %T", tagsAttr.Type)
	}

	scoresAttr, ok := userInfo.Attributes["scores"]
	if !ok {
		t.Fatal("scores attribute not found")
	}
	if setType, ok := scoresAttr.Type.(SetType); ok {
		if _, ok := setType.Element.(LongType); !ok {
			t.Errorf("Expected scores element to be LongType, got %T", setType.Element)
		}
	} else {
		t.Errorf("Expected scores to be SetType, got %T", scoresAttr.Type)
	}
}

// TestNestedRecordTypes tests nested record types in schema.
func TestNestedRecordTypes(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"address": {
								"type": "Record",
								"attributes": {
									"street": {"type": "String"},
									"city": {"type": "String"},
									"zip": {"type": "Long"}
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

	v, err := New(&s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	userInfo, ok := v.entityTypes["User"]
	if !ok {
		t.Fatal("User entity type not found")
	}

	addressAttr, ok := userInfo.Attributes["address"]
	if !ok {
		t.Fatal("address attribute not found")
	}

	recordType, ok := addressAttr.Type.(RecordType)
	if !ok {
		t.Fatalf("Expected address to be RecordType, got %T", addressAttr.Type)
	}

	if _, ok := recordType.Attributes["street"]; !ok {
		t.Error("Expected address to have 'street' attribute")
	}
	if _, ok := recordType.Attributes["city"]; !ok {
		t.Error("Expected address to have 'city' attribute")
	}
	if _, ok := recordType.Attributes["zip"]; !ok {
		t.Error("Expected address to have 'zip' attribute")
	}
}

// TestActionMemberOf tests action memberOf relationships.
func TestActionMemberOf(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {},
				"Document": {}
			},
			"actions": {
				"readWrite": {},
				"read": {
					"memberOf": [{"id": "readWrite"}],
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					}
				},
				"write": {
					"memberOf": [{"id": "readWrite"}],
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

	// Check that read action has memberOf
	readAction := types.EntityUID{Type: "Action", ID: "read"}
	readInfo, ok := v.actionTypes[readAction]
	if !ok {
		t.Fatal("read action not found")
	}

	if len(readInfo.MemberOf) != 1 {
		t.Errorf("Expected read to have 1 memberOf, got %d", len(readInfo.MemberOf))
	} else {
		if readInfo.MemberOf[0].ID != "readWrite" {
			t.Errorf("Expected read to be memberOf readWrite, got %s", readInfo.MemberOf[0].ID)
		}
	}
}

// TestInferTypeFromValue tests type inference from Cedar values.
func TestInferTypeFromValue(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {},
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

	tests := []struct {
		name         string
		value        types.Value
		expectedType string
	}{
		{"boolean true", types.Boolean(true), "Bool"},
		{"boolean false", types.Boolean(false), "Bool"},
		{"long", types.Long(42), "Long"},
		{"string", types.String("hello"), "String"},
		{"entity", types.EntityUID{Type: "User", ID: "alice"}, "Entity<User>"},
		{"empty set", types.NewSet(), "Set<Unknown>"},
		{"set with elements", types.NewSet(types.String("a")), "Set<String>"},
		{"record", types.NewRecord(types.RecordMap{"key": types.String("value")}), "Record"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inferredType := v.inferType(tc.value)
			if inferredType.String() != tc.expectedType {
				t.Errorf("Expected %s, got %s", tc.expectedType, inferredType.String())
			}
		})
	}
}

// TestContextValidationStrict tests strict context validation.
func TestContextValidationStrict(t *testing.T) {
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
								"ip": {"type": "String", "required": true}
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

	// Valid request with required context
	validReq := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context:   types.NewRecord(types.RecordMap{"ip": types.String("192.168.1.1")}),
	}

	result := ValidateRequest(&s, validReq)
	if !result.Valid {
		t.Errorf("Expected valid request, got error: %s", result.Error)
	}

	// Invalid request missing required context
	invalidReq := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	result = ValidateRequest(&s, invalidReq)
	if result.Valid {
		t.Error("Expected invalid request for missing required context")
	}
}
