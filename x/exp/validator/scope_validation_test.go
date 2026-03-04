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
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
)

// Scope and action validation tests.

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

			name:        "user for read/write set - valid because user can read",
			policy:      `permit(principal == User::"alice", action in [Action::"read", Action::"write"], resource);`,
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action in Action::"viewAll", resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal is User in Group::"admins", action, resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestExtractScopeTypeWithScopeIn(t *testing.T) {
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

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal in Group::"admins", action == Action::"view", resource);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)

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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action == Action::"view", resource is Document in Folder::"public");`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal == User::"alice", action == Action::"view", resource is Admin);`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if result.Valid {
		t.Error("Expected invalid for resource type not in allowed list")
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(s)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

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
			expectValid: true,
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

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
