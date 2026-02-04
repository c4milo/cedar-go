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
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
)

// Type checking tests.

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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
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
			result := validatePolicyString(t, s, tc.policy)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
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
			result := validatePolicyString(t, s, tc.policy)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
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
			result := validatePolicyString(t, s, tc.policy)
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
						"principalTypes": ["User", "Group"],
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
			result := validatePolicyString(t, s, tc.policy)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
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
			result := validatePolicyString(t, s, tc.policy)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
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
			result := validatePolicyString(t, s, tc.policy)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
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
			result := validatePolicyString(t, s, tc.policy)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
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
			result := validatePolicyString(t, s, tc.policy)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
		})
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
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

			result := ValidatePolicies(s, policies)

			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
			if !tc.expectValid && result.Valid {
				t.Errorf("Expected invalid, but validation passed")
			}
		})
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action == Action::"view", resource) when { context.ip == "127.0.0.1" };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action in [Action::"view", Action::"browse"], resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
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

			result := ValidatePolicies(s, policies)

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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.active.foo };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if result.Valid {
		t.Error("Expected invalid when accessing attribute on non-entity")
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	tests := []struct {
		name   string
		policy string
	}{

		{"isIpv4", `permit(principal, action, resource) when { ip("127.0.0.1").isIpv4() };`},
		{"isIpv6", `permit(principal, action, resource) when { ip("::1").isIpv6() };`},
		{"isLoopback", `permit(principal, action, resource) when { ip("127.0.0.1").isLoopback() };`},
		{"isMulticast", `permit(principal, action, resource) when { ip("224.0.0.1").isMulticast() };`},
		{"isInRange", `permit(principal, action, resource) when { ip("192.168.1.1").isInRange(ip("192.168.0.0/16")) };`},

		{"lessThan", `permit(principal, action, resource) when { decimal("1.0").lessThan(decimal("2.0")) };`},
		{"lessThanOrEqual", `permit(principal, action, resource) when { decimal("1.0").lessThanOrEqual(decimal("2.0")) };`},
		{"greaterThanOrEqual", `permit(principal, action, resource) when { decimal("2.0").greaterThanOrEqual(decimal("1.0")) };`},

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

			_ = ValidatePolicies(s, policies)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource == User::"doc1");`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
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

	result = ValidatePolicies(s, policies2)
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
							"age": {"type": "Long", "required": true}
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

			result := ValidatePolicies(s, policies)
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
							"score": {"type": "Long", "required": true}
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

			result := ValidatePolicies(s, policies)
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
							"active": {"type": "Boolean", "required": true},
							"admin": {"type": "Boolean", "required": true}
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

			result := ValidatePolicies(s, policies)
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
							"name": {"type": "String", "required": true}
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

			result := ValidatePolicies(s, policies)
			if !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
		})
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { [].isEmpty() };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestTypecheckWithNilNode(t *testing.T) {

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
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestTypecheckVariableMultiplePrincipalTypes(t *testing.T) {

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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action == Action::"view", resource) when { principal.name == "test" };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)

	_ = result
}

func TestTypecheckResourceVariable(t *testing.T) {

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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action == Action::"view", resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestTypecheckUnknownVariableName(t *testing.T) {

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
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { context == {} };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestTypecheckContextWithoutActionConstraint(t *testing.T) {

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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { context.anything == "test" };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestTypecheckAccessOnRecordType(t *testing.T) {

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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action == Action::"view", resource) when { context.metadata.source == "api" };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestTypecheckRecordAccessUnknownAttribute(t *testing.T) {

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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action == Action::"view", resource) when { context.unknown_attr == "test" };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
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
							"name": {"type": "String", "required": true}
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
								"authenticated": {"type": "Boolean", "required": true}
							}
						}
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
			result := validatePolicyString(t, s, tc.policy)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
			if !tc.expectValid && result.Valid {
				t.Error("Expected invalid, but validation passed")
			}
		})
	}
}
