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

	"github.com/cedar-policy/cedar-go/x/exp/schema"
)

// Tests for schema well-formedness validation.
// Validation happens at validator.New() time, not during schema parsing.
// This matches Cedar Rust's approach: lenient parsing + strict validation.

func TestSchemaValidation_DuplicatePrincipalTypes(t *testing.T) {
	// Duplicate types in principalTypes are allowed (semantically redundant but not invalid)
	// This matches Lean's behavior
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User", "User"],
						"resourceTypes": ["User"]
					}
				}
			}
		}
	}`
	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Schema parsing should succeed: %v", err)
	}
	v, err := New(s)
	if err != nil {
		t.Errorf("Duplicate principalTypes should be allowed: %v", err)
	}
	if v == nil {
		t.Error("Expected non-nil validator")
	}
}

func TestSchemaValidation_DuplicateResourceTypes(t *testing.T) {
	// Duplicate types in resourceTypes are allowed (semantically redundant but not invalid)
	// This matches Lean's behavior
	schemaJSON := `{
		"": {
			"entityTypes": {
				"Doc": {}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["Doc"],
						"resourceTypes": ["Doc", "Doc"]
					}
				}
			}
		}
	}`
	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Schema parsing should succeed: %v", err)
	}
	v, err := New(s)
	if err != nil {
		t.Errorf("Duplicate resourceTypes should be allowed: %v", err)
	}
	if v == nil {
		t.Error("Expected non-nil validator")
	}
}

func TestSchemaValidation_SelfReferenceMemberOf(t *testing.T) {
	// Direct self-reference is allowed - enables hierarchy within same type
	// (e.g., User in User for manager/employee relationships)
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"memberOfTypes": ["User"]
				}
			},
			"actions": {}
		}
	}`
	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Schema parsing should succeed: %v", err)
	}
	v, err := New(s)
	if err != nil {
		t.Errorf("Self-reference in memberOfTypes should be allowed: %v", err)
	}
	if v == nil {
		t.Error("Expected non-nil validator")
	}
}

func TestSchemaValidation_CyclicMemberOf_Allowed(t *testing.T) {
	// Cycles in memberOfTypes are ALLOWED. Cedar Rust and Lean do not check
	// for cycles at schema level - they only define allowed parent types.
	// Actual cycle detection happens at entity loading time.

	tests := []struct {
		name   string
		schema string
	}{
		{
			name: "indirect cycle A -> B -> C -> A",
			schema: `{
				"": {
					"entityTypes": {
						"A": {"memberOfTypes": ["B"]},
						"B": {"memberOfTypes": ["C"]},
						"C": {"memberOfTypes": ["A"]}
					},
					"actions": {}
				}
			}`,
		},
		{
			name: "direct cycle A -> B -> A",
			schema: `{
				"": {
					"entityTypes": {
						"A": {"memberOfTypes": ["B"]},
						"B": {"memberOfTypes": ["A"]}
					},
					"actions": {}
				}
			}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := schema.NewFromJSON([]byte(tc.schema))
			if err != nil {
				t.Fatalf("Schema parsing should succeed: %v", err)
			}
			v, err := New(s)
			if err != nil {
				t.Errorf("Cycles in memberOfTypes should be allowed: %v", err)
			}
			if v == nil {
				t.Error("Expected non-nil validator")
			}
		})
	}
}

func TestSchemaValidation_ActionWithoutAppliesTo(t *testing.T) {
	// Actions without appliesTo are allowed - they serve as action groups
	// that other actions can be members of
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {}
			},
			"actions": {
				"viewAll": {},
				"view": {
					"memberOf": [{"id": "viewAll"}],
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
		t.Fatalf("Schema parsing should succeed: %v", err)
	}
	v, err := New(s)
	if err != nil {
		t.Errorf("Actions without appliesTo (action groups) should be allowed: %v", err)
	}
	if v == nil {
		t.Error("Expected non-nil validator")
	}
}

func TestSchemaValidation_UnknownTypeInPrincipalTypes(t *testing.T) {
	// Unknown types in principalTypes should be rejected at validator creation.
	// This matches Cedar Rust's behavior.
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["NonExistent"],
						"resourceTypes": ["User"]
					}
				}
			}
		}
	}`
	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Schema parsing should succeed: %v", err)
	}
	_, err = New(s)
	if err == nil {
		t.Error("Expected validator creation to fail for schema with unknown principalType")
	}
	if !strings.Contains(err.Error(), "unknown") || !strings.Contains(err.Error(), "principalType") {
		t.Errorf("Expected error about unknown principalType, got: %v", err)
	}
}

func TestSchemaValidation_UnknownTypeInResourceTypes(t *testing.T) {
	// Unknown types in resourceTypes should be rejected at validator creation.
	// This matches Cedar Rust's behavior.
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["NonExistent"]
					}
				}
			}
		}
	}`
	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Schema parsing should succeed: %v", err)
	}
	_, err = New(s)
	if err == nil {
		t.Error("Expected validator creation to fail for schema with unknown resourceType")
	}
	if !strings.Contains(err.Error(), "unknown") || !strings.Contains(err.Error(), "resourceType") {
		t.Errorf("Expected error about unknown resourceType, got: %v", err)
	}
}

func TestSchemaValidation_UnknownTypeInMemberOf(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"memberOfTypes": ["NonExistent"]
				}
			},
			"actions": {}
		}
	}`
	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Schema parsing should succeed (lenient): %v", err)
	}
	_, err = New(s)
	if err == nil {
		t.Error("Expected validator creation to fail for schema with unknown type in memberOfTypes")
	}
	if !strings.Contains(err.Error(), "unknown") || !strings.Contains(err.Error(), "memberOfTypes") {
		t.Errorf("Expected error about unknown memberOfTypes, got: %v", err)
	}
}

func TestSchemaValidation_DuplicateMemberOfTypes(t *testing.T) {
	// Duplicate types in memberOfTypes are allowed (semantically redundant but not invalid)
	// This matches Lean's behavior
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {},
				"Admin": {
					"memberOfTypes": ["User", "User"]
				}
			},
			"actions": {}
		}
	}`
	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Schema parsing should succeed: %v", err)
	}
	v, err := New(s)
	if err != nil {
		t.Errorf("Duplicate memberOfTypes should be allowed: %v", err)
	}
	if v == nil {
		t.Error("Expected non-nil validator")
	}
}

func TestSchemaValidation_ValidSchema(t *testing.T) {
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
				},
				"edit": {
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
		t.Fatalf("Schema parsing should succeed: %v", err)
	}
	v, err := New(s)
	if err != nil {
		t.Errorf("Expected valid schema to pass validation, got error: %v", err)
	}
	if v == nil {
		t.Error("Expected non-nil validator")
	}
}

func TestSchemaValidation_ValidHierarchy(t *testing.T) {
	// Valid hierarchy: Admin -> Manager -> User (no cycles)
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {},
				"Manager": {"memberOfTypes": ["User"]},
				"Admin": {"memberOfTypes": ["Manager"]}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User", "Manager", "Admin"],
						"resourceTypes": ["User"]
					}
				}
			}
		}
	}`
	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Schema parsing should succeed: %v", err)
	}
	v, err := New(s)
	if err != nil {
		t.Errorf("Expected valid hierarchy to pass validation, got error: %v", err)
	}
	if v == nil {
		t.Error("Expected non-nil validator")
	}
}

func TestSchemaValidation_NamespacedSchema(t *testing.T) {
	// In namespaced schemas, local type names (without ::) are resolved
	// within the current namespace, similar to Cedar Rust behavior
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
		t.Fatalf("Schema parsing should succeed: %v", err)
	}
	v, err := New(s)
	if err != nil {
		t.Errorf("Expected valid namespaced schema to pass validation, got error: %v", err)
	}
	if v == nil {
		t.Error("Expected non-nil validator")
	}
}

func TestSchemaValidation_EmptySchema(t *testing.T) {
	// Empty schema (no entity types, no actions) - this should be valid
	// It's a minimal schema that simply has no definitions
	schemaJSON := `{"": {"entityTypes": {}, "actions": {}}}`
	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Schema parsing should succeed (lenient): %v", err)
	}
	// Empty schemas should be valid - they simply have no definitions
	v, err := New(s)
	if err != nil {
		t.Errorf("Empty schema should be valid: %v", err)
	}
	if v == nil {
		t.Error("Expected non-nil validator")
	}
}
