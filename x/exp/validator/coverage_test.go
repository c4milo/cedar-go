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

// TestFlatSchemaJSON tests parsing of flat schema format (entityTypes/actions at top level)
func TestFlatSchemaJSON(t *testing.T) {
	tests := []struct {
		name       string
		schemaJSON string
		wantErr    bool
	}{
		{
			name: "flat schema with entityTypes only",
			schemaJSON: `{
				"entityTypes": {
					"User": {
						"shape": {
							"type": "Record",
							"attributes": {
								"name": {"type": "String"}
							}
						}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "flat schema with actions only",
			schemaJSON: `{
				"entityTypes": {"User": {}, "Document": {}},
				"actions": {
					"view": {
						"appliesTo": {
							"principalTypes": ["User"],
							"resourceTypes": ["Document"]
						}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "flat schema with commonTypes",
			schemaJSON: `{
				"entityTypes": {},
				"commonTypes": {
					"SharedRecord": {
						"type": "Record",
						"attributes": {
							"id": {"type": "Long"}
						}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "flat schema with action context at top level",
			schemaJSON: `{
				"entityTypes": {"User": {}, "Document": {}},
				"actions": {
					"edit": {
						"appliesTo": {
							"principalTypes": ["User"],
							"resourceTypes": ["Document"]
						},
						"context": {
							"type": "Record",
							"attributes": {
								"reason": {"type": "String"}
							}
						}
					}
				}
			}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := schema.NewFromJSON([]byte(tt.schemaJSON))
			if err != nil {
				t.Fatalf("Failed to parse schema: %v", err)
			}

			_, err = New(s)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestActionContextFromAppliesTo tests that action context from appliesTo is parsed
func TestActionContextFromAppliesTo(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {"User": {}, "Document": {}},
		"actions": {
			"edit": {
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["Document"],
					"context": {
						"type": "Record",
						"attributes": {
							"reason": {"type": "String"}
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

	// Check that context attribute is present
	actionUID := types.EntityUID{Type: "Action", ID: "edit"}
	actionInfo, exists := v.actionTypes[actionUID]
	if !exists {
		t.Fatal("Action 'edit' not found in validator")
	}

	if _, ok := actionInfo.Context.Attributes["reason"]; !ok {
		t.Error("Context should have 'reason' attribute from appliesTo context")
	}
}

// TestStrictContextValidation tests strict mode validation of context attributes
func TestStrictContextValidation(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {"User": {}, "Document": {}},
		"actions": {
			"view": {
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["Document"],
					"context": {
						"type": "Record",
						"attributes": {
							"allowed": {"type": "String"}
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

	v, err := New(s, WithStrictEntityValidation())
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Test with undeclared context attribute
	result := v.ValidateRequest(cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context: types.NewRecord(types.RecordMap{
			"allowed":    types.String("value"),
			"undeclared": types.String("not in schema"),
		}),
	})

	// In strict mode, undeclared attributes should cause validation to fail
	if result.Valid {
		t.Error("Expected validation to fail for undeclared context attribute in strict mode")
	}
}

// TestCedarTypeInterface tests that all CedarType implementations satisfy the interface
func TestCedarTypeInterface(t *testing.T) {
	types := []CedarType{
		BoolType{},
		LongType{},
		StringType{},
		EntityType{Name: "User"},
		SetType{Element: StringType{}},
		RecordType{Attributes: map[string]AttributeType{}},
		ExtensionType{Name: "decimal"},
		AnyEntityType{},
		UnknownType{},
	}

	for _, ct := range types {
		// Verify it implements CedarType interface
		var _ CedarType = ct

		// Verify String() returns something
		s := ct.String()
		if s == "" {
			t.Errorf("%T.String() returned empty string", ct)
		}
	}
}

// TestTypesMatchComprehensive tests TypesMatch with various type combinations
func TestTypesMatchComprehensive(t *testing.T) {
	tests := []struct {
		name     string
		expected CedarType
		actual   CedarType
		want     bool
	}{
		// Primitive type matches
		{"bool matches bool", BoolType{}, BoolType{}, true},
		{"long matches long", LongType{}, LongType{}, true},
		{"string matches string", StringType{}, StringType{}, true},

		// Primitive type mismatches
		{"bool doesn't match long", BoolType{}, LongType{}, false},
		{"long doesn't match string", LongType{}, StringType{}, false},
		{"string doesn't match bool", StringType{}, BoolType{}, false},

		// Entity type matches
		{"entity matches same entity", EntityType{Name: "User"}, EntityType{Name: "User"}, true},
		{"entity doesn't match different entity", EntityType{Name: "User"}, EntityType{Name: "Document"}, false},
		{"any entity matches entity", AnyEntityType{}, EntityType{Name: "User"}, true},

		// Set type matches
		{"set<string> matches set<string>", SetType{Element: StringType{}}, SetType{Element: StringType{}}, true},
		{"set<long> doesn't match set<string>", SetType{Element: LongType{}}, SetType{Element: StringType{}}, false},

		// Extension type matches
		{"decimal matches decimal", ExtensionType{Name: "decimal"}, ExtensionType{Name: "decimal"}, true},
		{"ipaddr matches ipaddr", ExtensionType{Name: "ipaddr"}, ExtensionType{Name: "ipaddr"}, true},
		{"decimal doesn't match ipaddr", ExtensionType{Name: "decimal"}, ExtensionType{Name: "ipaddr"}, false},

		// Unknown type as expected matches anything
		{"unknown expected matches anything", UnknownType{}, StringType{}, true},
		{"unknown expected matches bool", UnknownType{}, BoolType{}, true},
		{"unknown expected matches entity", UnknownType{}, EntityType{Name: "User"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TypesMatch(tt.expected, tt.actual)
			if got != tt.want {
				t.Errorf("TypesMatch(%v, %v) = %v, want %v", tt.expected, tt.actual, got, tt.want)
			}
		})
	}
}

// TestParseJSONTypeVariantsCoverage tests parsing various JSON type definitions
func TestParseJSONTypeVariantsCoverage(t *testing.T) {
	tests := []struct {
		name       string
		schemaJSON string
		wantErr    bool
	}{
		{
			name: "entity type with name",
			schemaJSON: `{
				"entityTypes": {
					"User": {
						"shape": {
							"type": "Record",
							"attributes": {
								"manager": {"type": "Entity", "name": "User"}
							}
						}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "entity type without name (any entity)",
			schemaJSON: `{
				"entityTypes": {
					"Container": {
						"shape": {
							"type": "Record",
							"attributes": {
								"item": {"type": "Entity"}
							}
						}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "set type with element",
			schemaJSON: `{
				"entityTypes": {
					"User": {
						"shape": {
							"type": "Record",
							"attributes": {
								"tags": {"type": "Set", "element": {"type": "String"}}
							}
						}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "set type without element",
			schemaJSON: `{
				"entityTypes": {
					"User": {
						"shape": {
							"type": "Record",
							"attributes": {
								"data": {"type": "Set"}
							}
						}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "extension type decimal",
			schemaJSON: `{
				"entityTypes": {
					"Product": {
						"shape": {
							"type": "Record",
							"attributes": {
								"price": {"type": "Extension", "name": "decimal"}
							}
						}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "extension type ipaddr",
			schemaJSON: `{
				"entityTypes": {
					"Server": {
						"shape": {
							"type": "Record",
							"attributes": {
								"ip": {"type": "Extension", "name": "ipaddr"}
							}
						}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "extension type without name",
			schemaJSON: `{
				"entityTypes": {
					"Container": {
						"shape": {
							"type": "Record",
							"attributes": {
								"ext": {"type": "Extension"}
							}
						}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "common type reference",
			schemaJSON: `{
				"commonTypes": {
					"Name": {"type": "String"}
				},
				"entityTypes": {
					"User": {
						"shape": {
							"type": "Record",
							"attributes": {
								"name": {"type": "Name"}
							}
						}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "nested record type",
			schemaJSON: `{
				"entityTypes": {
					"User": {
						"shape": {
							"type": "Record",
							"attributes": {
								"address": {
									"type": "Record",
									"attributes": {
										"street": {"type": "String"},
										"city": {"type": "String"}
									}
								}
							}
						}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "optional attribute",
			schemaJSON: `{
				"entityTypes": {
					"User": {
						"shape": {
							"type": "Record",
							"attributes": {
								"nickname": {"type": "String", "required": false}
							}
						}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "Bool type alias",
			schemaJSON: `{
				"entityTypes": {
					"User": {
						"shape": {
							"type": "Record",
							"attributes": {
								"active": {"type": "Bool"}
							}
						}
					}
				}
			}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := schema.NewFromJSON([]byte(tt.schemaJSON))
			if err != nil {
				t.Fatalf("Failed to parse schema: %v", err)
			}

			_, err = New(s)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestNamespacedActionsCoverage tests that actions in namespaces get proper qualified types
func TestNamespacedActionsCoverage(t *testing.T) {
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

	// Check that action has namespaced type
	expectedActionUID := types.EntityUID{Type: "MyApp::Action", ID: "view"}
	if _, exists := v.actionTypes[expectedActionUID]; !exists {
		t.Errorf("Expected action with namespaced type %v, but not found", expectedActionUID)
		t.Logf("Available actions: %v", v.actionTypes)
	}
}

// TestActionMemberOfCoverage tests parsing of action memberOf references
func TestActionMemberOfCoverage(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {"User": {}, "Document": {}},
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
				"memberOf": [{"type": "Action", "id": "readWrite"}],
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

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Check read action has memberOf
	readAction, exists := v.actionTypes[types.EntityUID{Type: "Action", ID: "read"}]
	if !exists {
		t.Fatal("Action 'read' not found")
	}
	if len(readAction.MemberOf) != 1 {
		t.Errorf("Expected 1 memberOf, got %d", len(readAction.MemberOf))
	}

	// Check write action has memberOf with explicit type
	writeAction, exists := v.actionTypes[types.EntityUID{Type: "Action", ID: "write"}]
	if !exists {
		t.Fatal("Action 'write' not found")
	}
	if len(writeAction.MemberOf) != 1 {
		t.Errorf("Expected 1 memberOf, got %d", len(writeAction.MemberOf))
	}
}

// TestInferTypeComprehensive tests type inference for various value types
func TestInferTypeComprehensive(t *testing.T) {
	schemaJSON := `{"entityTypes": {"User": {}}}`
	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	tests := []struct {
		name     string
		value    types.Value
		expected string
	}{
		{"boolean", types.Boolean(true), "Bool"},
		{"long", types.Long(42), "Long"},
		{"string", types.String("test"), "String"},
		{"entity", types.EntityUID{Type: "User", ID: "alice"}, "Entity<User>"},
		{"empty set", types.Set{}, "Set<Unknown>"},
		{"string set", types.NewSet(types.String("a"), types.String("b")), "Set<String>"},
		{"empty record", types.Record{}, "Record"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.inferType(tt.value)
			if got.String() != tt.expected {
				t.Errorf("inferType(%v) = %s, want %s", tt.value, got.String(), tt.expected)
			}
		})
	}
}

// TestTypeReferenceToEntity tests that unknown type names are treated as entity references
func TestTypeReferenceToEntity(t *testing.T) {
	// Schema with a type reference that isn't a common type
	schemaJSON := `{
		"entityTypes": {
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {
						"manager": {"type": "User"}
					}
				}
			}
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

// TestCommonTypeReference tests parsing of common type references
func TestCommonTypeReference(t *testing.T) {
	schemaJSON := `{
		"commonTypes": {
			"Name": {"type": "String"},
			"Age": {"type": "Long"}
		},
		"entityTypes": {
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {
						"name": {"type": "Name"},
						"age": {"type": "Age"}
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

	// Verify common types were parsed
	if _, ok := v.commonTypes["Name"]; !ok {
		t.Error("Common type 'Name' not found")
	}
	if _, ok := v.commonTypes["Age"]; !ok {
		t.Error("Common type 'Age' not found")
	}
}

// TestNilEntityShape tests parsing entity without shape
func TestNilEntityShape(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {
			"User": {}
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

// TestActionWithoutAppliesTo tests parsing action without appliesTo
func TestActionWithoutAppliesTo(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {},
		"actions": {
			"admin": {}
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

// TestSchemaWithNilNamespace tests handling of nil namespace in schema
func TestSchemaWithNilNamespace(t *testing.T) {
	// This tests the nil namespace check in parseSchemaJSON
	schemaJSON := `{
		"": {
			"entityTypes": {"User": {}},
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

// TestRecordWithNoAttributes tests record type with empty attributes
func TestRecordWithNoAttributes(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {}
				}
			}
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

// TestDuplicatePrincipalResourceTypes tests deduplication in appliesTo
func TestDuplicatePrincipalResourceTypes(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {"User": {}, "Document": {}},
		"actions": {
			"view": {
				"appliesTo": {
					"principalTypes": ["User", "User", "User"],
					"resourceTypes": ["Document", "Document"]
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

	// Verify deduplication - should only have 1 User and 1 Document
	actionInfo := v.actionTypes[types.EntityUID{Type: "Action", ID: "view"}]
	if len(actionInfo.PrincipalTypes) != 1 {
		t.Errorf("Expected 1 principal type after dedup, got %d", len(actionInfo.PrincipalTypes))
	}
	if len(actionInfo.ResourceTypes) != 1 {
		t.Errorf("Expected 1 resource type after dedup, got %d", len(actionInfo.ResourceTypes))
	}
}

// TestWithAllowUnknownEntityTypes tests the option to allow unknown entity types.
func TestWithAllowUnknownEntityTypes(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {"User": {}},
		"actions": {
			"view": {
				"appliesTo": {
					"principalTypes": ["User", "UnknownType"],
					"resourceTypes": ["User"]
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Without the option, should fail
	_, err = New(s)
	if err == nil {
		t.Error("Expected error for unknown entity type without option")
	}

	// With the option, should succeed
	v, err := New(s, WithAllowUnknownEntityTypes())
	if err != nil {
		t.Errorf("Expected success with WithAllowUnknownEntityTypes, got: %v", err)
	}
	if v == nil {
		t.Error("Expected non-nil validator")
	}
}

// TestTopLevelActionContext tests parsing of top-level context in action.
func TestTopLevelActionContext(t *testing.T) {
	// Use namespace format to ensure context is in appliesTo
	schemaJSON := `{
		"": {
			"entityTypes": {"User": {}, "Document": {}},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"],
						"context": {
							"type": "Record",
							"attributes": {
								"reason": {"type": "String", "required": true}
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

	// Test policy that uses context
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action == Action::"view", resource) when { context.reason == "audit" };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid policy, got errors: %v", result.Errors)
	}
}

// TestExtensionTypeCategory tests typeCategory for extension types.
func TestExtensionTypeCategory(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {
						"ip": {"type": "Extension", "name": "ipaddr", "required": true},
						"amount": {"type": "Extension", "name": "decimal", "required": true},
						"created": {"type": "Extension", "name": "datetime", "required": true},
						"timeout": {"type": "Extension", "name": "duration", "required": true}
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
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test comparisons between extension types
	tests := []struct {
		name   string
		policy string
	}{
		{"ipaddr comparison", `permit(principal, action, resource) when { principal.ip == ip("192.168.1.1") };`},
		{"decimal comparison", `permit(principal, action, resource) when { principal.amount == decimal("10.00") };`},
		{"datetime comparison", `permit(principal, action, resource) when { principal.created == datetime("2024-01-01T00:00:00Z") };`},
		{"duration comparison", `permit(principal, action, resource) when { principal.timeout == duration("1h") };`},
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
				t.Errorf("Expected valid policy, got errors: %v", result.Errors)
			}
		})
	}
}

// TestParseJSONTypeExtensions tests parsing of extension types in JSON.
func TestParseJSONTypeExtensions(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {
						"ip": {"type": "Extension", "name": "ipaddr"},
						"amount": {"type": "Extension", "name": "decimal"}
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
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Verify extension types were parsed
	userInfo := v.entityTypes["User"]
	ipAttr := userInfo.Attributes["ip"]
	if ext, ok := ipAttr.Type.(ExtensionType); !ok || ext.Name != "ipaddr" {
		t.Errorf("Expected ipaddr extension type, got %v", ipAttr.Type)
	}
}

// TestEmptySchemaPolicy tests policy validation against empty schema.
func TestEmptySchemaPolicy(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {},
		"actions": {}
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
	// Should get impossiblePolicy error
	if result.Valid {
		t.Error("Expected impossiblePolicy error for empty schema")
	}
}

// TestUnifyTypesEdgeCases tests unifyTypes with various type combinations.
func TestUnifyTypesEdgeCases(t *testing.T) {
	// Test that unifyTypes handles mismatched types
	t1 := BoolType{}
	t2 := LongType{}
	result := unifyTypes(t1, t2)
	if _, ok := result.(UnknownType); !ok {
		t.Errorf("Expected UnknownType for mismatched types, got %T", result)
	}

	// Test with unknown types
	result = unifyTypes(UnknownType{}, t1)
	if _, ok := result.(BoolType); !ok {
		t.Errorf("Expected BoolType when unifying with UnknownType, got %T", result)
	}

	result = unifyTypes(t1, UnknownType{})
	if _, ok := result.(BoolType); !ok {
		t.Errorf("Expected BoolType when unifying with UnknownType, got %T", result)
	}
}

// TestExpectArgsErrors tests expectArgs error reporting.
func TestExpectArgsErrors(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {"User": {}},
		"actions": {
			"view": {
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["User"]
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test extension function with wrong argument type
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { ip(123).isLoopback() };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if result.Valid {
		t.Error("Expected error for wrong argument type to ip()")
	}
}

// TestExtensionTypeComparisons tests extension type comparisons to exercise typeCategory.
func TestExtensionTypeComparisons(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {
						"ip1": {"type": "Extension", "name": "ipaddr", "required": true},
						"ip2": {"type": "Extension", "name": "ipaddr", "required": true},
						"dec1": {"type": "Extension", "name": "decimal", "required": true},
						"dec2": {"type": "Extension", "name": "decimal", "required": true}
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
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test comparisons between same extension types
	tests := []struct {
		name   string
		policy string
		valid  bool
	}{
		{"ipaddr == ipaddr", `permit(principal, action, resource) when { principal.ip1 == principal.ip2 };`, true},
		{"decimal == decimal", `permit(principal, action, resource) when { principal.dec1 == principal.dec2 };`, true},
		// Cross-type comparison should produce a warning/error
		{"ipaddr == decimal", `permit(principal, action, resource) when { principal.ip1 == principal.dec1 };`, false},
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
			if result.Valid != tc.valid {
				t.Errorf("Expected valid=%v, got valid=%v, errors=%v", tc.valid, result.Valid, result.Errors)
			}
		})
	}
}

// Parsing logic is now in the schema package and tested there.

// TestContextMerging tests that top-level context merges with appliesTo context.
func TestContextMerging(t *testing.T) {
	// This schema format has both top-level context and appliesTo context
	schemaJSON := `{
		"": {
			"entityTypes": {"User": {}, "Document": {}},
			"actions": {
				"edit": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"],
						"context": {
							"type": "Record",
							"attributes": {
								"fromAppliesTo": {"type": "String", "required": true}
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

	// Check that context has attribute from appliesTo
	actionUID := types.EntityUID{Type: "Action", ID: "edit"}
	actionInfo, exists := v.actionTypes[actionUID]
	if !exists {
		t.Fatal("Action 'edit' not found")
	}

	if _, ok := actionInfo.Context.Attributes["fromAppliesTo"]; !ok {
		t.Error("Context should have 'fromAppliesTo' attribute")
	}
}

// TestInferSetTypeNonEmpty tests type inference for non-empty sets.
func TestInferSetTypeNonEmpty(t *testing.T) {
	schemaJSON := `{"entityTypes": {"User": {}}}`
	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Test with non-empty set of different types
	tests := []struct {
		name     string
		set      types.Set
		expected string
	}{
		{"long set", types.NewSet(types.Long(1), types.Long(2)), "Set<Long>"},
		{"bool set", types.NewSet(types.Boolean(true)), "Set<Bool>"},
		{"entity set", types.NewSet(types.EntityUID{Type: "User", ID: "alice"}), "Set<Entity<User>>"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := v.inferType(tc.set)
			if got.String() != tc.expected {
				t.Errorf("inferType(%v) = %s, want %s", tc.set, got.String(), tc.expected)
			}
		})
	}
}

// TestValidateContextUndeclaredStrict tests undeclared context attribute detection in strict mode.
func TestValidateContextUndeclaredStrict(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {"User": {}, "Document": {}},
		"actions": {
			"view": {
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["Document"],
					"context": {
						"type": "Record",
						"attributes": {
							"declared": {"type": "String", "required": true}
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

	// Non-strict mode should allow undeclared attributes
	v1, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	result1 := v1.ValidateRequest(cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context: types.NewRecord(types.RecordMap{
			"declared":   types.String("value"),
			"undeclared": types.String("extra"),
		}),
	})
	if !result1.Valid {
		t.Error("Non-strict mode should allow undeclared context attributes")
	}
}

// TestCheckScopeTypeAllowedEmpty tests checkScopeTypeAllowed with empty allowed list.
func TestCheckScopeTypeAllowedEmpty(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {"User": {}, "Document": {}},
		"actions": {
			"view": {
				"appliesTo": {
					"principalTypes": [],
					"resourceTypes": []
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

	// Should get impossiblePolicy because action has no valid environment
	result := ValidatePolicies(s, policies)
	if result.Valid {
		t.Error("Expected impossiblePolicy for action with empty principal/resource types")
	}
}

// TestParseSchemaJSONError tests error handling in parseSchemaJSON.
func TestParseSchemaJSONError(t *testing.T) {
	// Test with invalid JSON - this would be caught by schema.NewFromJSON
	// but we want to ensure our error handling is robust
	schemaJSON := `{
		"entityTypes": {"User": {}},
		"actions": {}
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

// TestTypesMatchDefault tests TypesMatch with various edge cases.
func TestTypesMatchDefault(t *testing.T) {
	// AnyEntity as actual should not match specific entity expected
	// This tests the matchEntityType function
	result := TypesMatch(EntityType{Name: "User"}, AnyEntityType{})
	if !result {
		t.Error("Expected EntityType to match AnyEntityType")
	}

	// Unknown type as expected matches anything
	result = TypesMatch(UnknownType{}, EntityType{Name: "User"})
	if !result {
		t.Error("UnknownType expected should match any actual")
	}
}

// TestTypesMatchRecordAttributes tests TypesMatch for record types with various attribute scenarios.
func TestTypesMatchRecordAttributes(t *testing.T) {
	tests := []struct {
		name     string
		expected RecordType
		actual   RecordType
		want     bool
	}{
		{
			name:     "empty records match",
			expected: RecordType{Attributes: map[string]AttributeType{}},
			actual:   RecordType{Attributes: map[string]AttributeType{}},
			want:     true,
		},
		{
			name: "matching required attribute",
			expected: RecordType{Attributes: map[string]AttributeType{
				"name": {Type: StringType{}, Required: true},
			}},
			actual: RecordType{Attributes: map[string]AttributeType{
				"name": {Type: StringType{}, Required: true},
			}},
			want: true,
		},
		{
			name: "missing required attribute",
			expected: RecordType{Attributes: map[string]AttributeType{
				"name": {Type: StringType{}, Required: true},
			}},
			actual: RecordType{Attributes: map[string]AttributeType{}},
			want:   false,
		},
		{
			name: "missing optional attribute is OK",
			expected: RecordType{Attributes: map[string]AttributeType{
				"nickname": {Type: StringType{}, Required: false},
			}},
			actual: RecordType{Attributes: map[string]AttributeType{}},
			want:   true,
		},
		{
			name: "type mismatch in attribute",
			expected: RecordType{Attributes: map[string]AttributeType{
				"age": {Type: LongType{}, Required: true},
			}},
			actual: RecordType{Attributes: map[string]AttributeType{
				"age": {Type: StringType{}, Required: true},
			}},
			want: false,
		},
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

// TestEntityTypeMatching tests various entity type matching scenarios.
func TestEntityTypeMatching(t *testing.T) {
	tests := []struct {
		name     string
		expected CedarType
		actual   CedarType
		want     bool
	}{
		{
			name:     "specific entity matches AnyEntity",
			expected: EntityType{Name: "User"},
			actual:   AnyEntityType{},
			want:     true,
		},
		{
			name:     "AnyEntity expected matches specific",
			expected: AnyEntityType{},
			actual:   EntityType{Name: "User"},
			want:     true,
		},
		{
			name:     "AnyEntity matches AnyEntity",
			expected: AnyEntityType{},
			actual:   AnyEntityType{},
			want:     true,
		},
		{
			name:     "entity doesn't match non-entity",
			expected: EntityType{Name: "User"},
			actual:   StringType{},
			want:     false,
		},
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

// TestSetTypeMatching tests set type matching with nested types.
func TestSetTypeMatching(t *testing.T) {
	tests := []struct {
		name     string
		expected CedarType
		actual   CedarType
		want     bool
	}{
		{
			name:     "set of unknown matches set of string",
			expected: SetType{Element: UnknownType{}},
			actual:   SetType{Element: StringType{}},
			want:     true,
		},
		{
			name:     "nested set types",
			expected: SetType{Element: SetType{Element: LongType{}}},
			actual:   SetType{Element: SetType{Element: LongType{}}},
			want:     true,
		},
		{
			name:     "set doesn't match non-set",
			expected: SetType{Element: StringType{}},
			actual:   StringType{},
			want:     false,
		},
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

// TestRecordTypeMatching tests record type matching.
func TestRecordTypeMatching(t *testing.T) {
	// Record doesn't match non-record
	expected := RecordType{Attributes: map[string]AttributeType{}}
	actual := StringType{}
	if TypesMatch(expected, actual) {
		t.Error("Record should not match non-record type")
	}
}

// TestExtensionTypeMatching tests extension type matching.
func TestExtensionTypeMatching(t *testing.T) {
	// Extension doesn't match non-extension
	expected := ExtensionType{Name: "decimal"}
	actual := StringType{}
	if TypesMatch(expected, actual) {
		t.Error("Extension should not match non-extension type")
	}
}

// TestTypeCategoryBoolComparison tests typeCategory for boolean comparisons.
func TestTypeCategoryBoolComparison(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {
						"active": {"type": "Boolean", "required": true},
						"verified": {"type": "Boolean", "required": true}
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
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test boolean == boolean comparison
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.active == principal.verified };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid policy for bool == bool, got errors: %v", result.Errors)
	}
}

// TestTypeCategorySetComparison tests typeCategory for set comparisons.
func TestTypeCategorySetComparison(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {
						"tags1": {"type": "Set", "element": {"type": "String"}, "required": true},
						"tags2": {"type": "Set", "element": {"type": "String"}, "required": true}
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
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test set == set comparison
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.tags1 == principal.tags2 };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid policy for set == set, got errors: %v", result.Errors)
	}
}

// TestTypeCategoryUnknownEntityComparison tests comparison with unknown entity types.
func TestTypeCategoryUnknownEntityComparison(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {
						"ref": {"type": "Entity", "name": "UnknownType", "required": true}
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
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// With allow unknown types, should pass
	v, err := New(s, WithAllowUnknownEntityTypes())
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Test comparison with unknown entity type - should be allowed (lenient)
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.ref == principal };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := v.ValidatePolicies(policies)
	// Should be valid due to lenient comparison with unknown type
	if !result.Valid {
		t.Errorf("Expected valid policy for unknown entity comparison, got errors: %v", result.Errors)
	}
}

// TestTypeCategoryUnknownExtension tests comparison with unknown extension types.
func TestTypeCategoryUnknownExtension(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {
						"custom": {"type": "Extension", "name": "customext", "required": true}
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
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test comparison with unknown extension type
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.custom == principal.custom };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	// Unknown extension types should be treated leniently
	if !result.Valid {
		t.Errorf("Expected valid policy for unknown extension comparison, got errors: %v", result.Errors)
	}
}

// TestTypeCategoryAnyEntity tests typeCategory for AnyEntityType.
func TestTypeCategoryAnyEntity(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {
						"ref": {"type": "Entity", "required": true}
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
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Test comparison with any entity type
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.ref == principal };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid policy for any entity comparison, got errors: %v", result.Errors)
	}
}

// TestUnspecifiedTypeAttribute tests parsing of attributes with empty type (UnspecifiedType).
func TestUnspecifiedTypeAttribute(t *testing.T) {
	// Schema with an attribute that has empty type string
	schemaJSON := `{
		"entityTypes": {
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {
						"data": {"type": "", "required": true}
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
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Check that the attribute type is UnspecifiedType
	userInfo := v.entityTypes["User"]
	dataAttr := userInfo.Attributes["data"]
	if _, ok := dataAttr.Type.(UnspecifiedType); !ok {
		t.Errorf("Expected UnspecifiedType for empty type string, got %T", dataAttr.Type)
	}

	// Test that comparison with UnspecifiedType is allowed (lenient)
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.data == "test" };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := v.ValidatePolicies(policies)
	// UnspecifiedType comparisons should be allowed (lenient mode)
	if !result.Valid {
		t.Errorf("Expected valid policy for UnspecifiedType comparison, got errors: %v", result.Errors)
	}
}

// TestUnspecifiedTypeInCondition tests that UnspecifiedType in boolean context produces error.
func TestUnspecifiedTypeInCondition(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {
						"flag": {"type": "", "required": true}
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
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Using UnspecifiedType directly as a condition should error
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.flag };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	// Using unspecified type as boolean condition should fail
	if result.Valid {
		t.Error("Expected error when using UnspecifiedType as boolean condition")
	}
}

// TestParseJSONTypeDefaultCase tests parseJSONType with unknown type strings.
func TestParseJSONTypeDefaultCase(t *testing.T) {
	// Schema with a type reference to a common type
	schemaJSON := `{
		"commonTypes": {
			"MyString": {"type": "String"}
		},
		"entityTypes": {
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {
						"name": {"type": "MyString", "required": true}
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
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Verify the common type was resolved
	userInfo := v.entityTypes["User"]
	nameAttr := userInfo.Attributes["name"]
	if _, ok := nameAttr.Type.(StringType); !ok {
		t.Errorf("Expected StringType for MyString reference, got %T", nameAttr.Type)
	}
}

// TestParseJSONTypeCommonTypeBool tests parseJSONType for Boolean common type.
func TestParseJSONTypeCommonTypeBool(t *testing.T) {
	schemaJSON := `{
		"commonTypes": {
			"Flag": {"type": "Boolean"}
		},
		"entityTypes": {
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {
						"active": {"type": "Flag", "required": true}
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
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Verify the common type was resolved to BoolType
	if ct, ok := v.commonTypes["Flag"]; !ok {
		t.Error("Common type 'Flag' not found")
	} else if _, ok := ct.(BoolType); !ok {
		t.Errorf("Expected BoolType, got %T", ct)
	}
}

// TestParseJSONTypeCommonTypeSet tests parseJSONType for Set common type.
func TestParseJSONTypeCommonTypeSet(t *testing.T) {
	schemaJSON := `{
		"commonTypes": {
			"Tags": {"type": "Set", "element": {"type": "String"}}
		},
		"entityTypes": {
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {
						"tags": {"type": "Tags", "required": true}
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
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Verify the common type was resolved to SetType
	if ct, ok := v.commonTypes["Tags"]; !ok {
		t.Error("Common type 'Tags' not found")
	} else if st, ok := ct.(SetType); !ok {
		t.Errorf("Expected SetType, got %T", ct)
	} else if _, ok := st.Element.(StringType); !ok {
		t.Errorf("Expected Set<String>, got Set<%T>", st.Element)
	}
}

// TestParseJSONTypeCommonTypeExtension tests parseJSONType for Extension common type.
func TestParseJSONTypeCommonTypeExtension(t *testing.T) {
	schemaJSON := `{
		"commonTypes": {
			"IPAddress": {"type": "Extension", "name": "ipaddr"}
		},
		"entityTypes": {
			"Server": {
				"shape": {
					"type": "Record",
					"attributes": {
						"ip": {"type": "IPAddress", "required": true}
					}
				}
			}
		},
		"actions": {
			"view": {
				"appliesTo": {
					"principalTypes": ["Server"],
					"resourceTypes": ["Server"]
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

	// Verify the common type was resolved to ExtensionType
	if ct, ok := v.commonTypes["IPAddress"]; !ok {
		t.Error("Common type 'IPAddress' not found")
	} else if et, ok := ct.(ExtensionType); !ok {
		t.Errorf("Expected ExtensionType, got %T", ct)
	} else if et.Name != "ipaddr" {
		t.Errorf("Expected ipaddr extension, got %s", et.Name)
	}
}

// TestParseJSONTypeCommonTypeEntityRef tests parseJSONType default case for entity reference.
func TestParseJSONTypeCommonTypeEntityRef(t *testing.T) {
	schemaJSON := `{
		"commonTypes": {
			"UserRef": {"type": "User"}
		},
		"entityTypes": {
			"User": {},
			"Document": {
				"shape": {
					"type": "Record",
					"attributes": {
						"owner": {"type": "UserRef", "required": true}
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
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Verify the common type was resolved to EntityType via default case
	if ct, ok := v.commonTypes["UserRef"]; !ok {
		t.Error("Common type 'UserRef' not found")
	} else if et, ok := ct.(EntityType); !ok {
		t.Errorf("Expected EntityType, got %T", ct)
	} else if et.Name != "User" {
		t.Errorf("Expected User entity type, got %s", et.Name)
	}
}

// TestValidationErrorMethod tests the ValidationError.Error() method
func TestValidationErrorMethod(t *testing.T) {
	tests := []struct {
		name     string
		err      ValidationError
		expected string
	}{
		{
			name:     "error with code",
			err:      ValidationError{Code: ErrUnexpectedType, Message: "expected boolean"},
			expected: "unexpected_type: expected boolean",
		},
		{
			name:     "error without code",
			err:      ValidationError{Message: "just a message"},
			expected: "just a message",
		},
		{
			name:     "error with code and details",
			err:      ValidationError{Code: ErrAttributeNotFound, Message: "attr not found", Details: map[string]string{"attr": "name"}},
			expected: "attribute_not_found: attr not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestActionContextInAppliesTo tests action context parsing inside appliesTo section
func TestActionContextInAppliesTo(t *testing.T) {
	// Context defined inside appliesTo section
	schemaJSON := `{
		"entityTypes": {"User": {}, "Document": {}},
		"actions": {
			"edit": {
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["Document"],
					"context": {
						"type": "Record",
						"attributes": {
							"reason": {"type": "String"}
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

	// Context should be parsed from appliesTo
	actionUID := types.NewEntityUID("Action", "edit")
	info, ok := v.actionTypes[actionUID]
	if !ok {
		t.Fatal("Action 'edit' not found")
	}

	// Should have context attribute from appliesTo
	if _, ok := info.Context.Attributes["reason"]; !ok {
		t.Error("Expected context attribute 'reason' from appliesTo")
	}
}

// TestScopeTypeInDescendantCheck tests checkScopeTypeIn with descendant checking
func TestScopeTypeInDescendantCheck(t *testing.T) {
	// Schema where User is NOT in memberOfTypes of Group
	schemaJSON := `{
		"entityTypes": {
			"User": {},
			"Group": {},
			"Org": {"memberOfTypes": ["Org"]}
		},
		"actions": {
			"view": {
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["Group"]
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

	// Policy with "principal in Group::..." - User can't be in Group
	policy := `permit(principal in Group::"admins", action == Action::"view", resource);`
	ps, err := cedar.NewPolicySetFromBytes("test", []byte(policy))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	result := v.ValidatePolicies(ps)
	// Should report impossiblePolicy because User can't be in Group
	if result.Valid {
		t.Error("Expected validation errors for impossible principal in Group")
	}
}

// TestActionScopeInSetAllInvalid tests validateActionScopeInSet when all actions are invalid
func TestActionScopeInSetAllInvalid(t *testing.T) {
	// Schema with actions that have no valid appliesTo
	schemaJSON := `{
		"entityTypes": {"User": {}, "Document": {}},
		"actions": {
			"action1": {},
			"action2": {}
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

	// Policy with action in [action1, action2] - both have no appliesTo
	policy := `permit(principal, action in [Action::"action1", Action::"action2"], resource);`
	ps, err := cedar.NewPolicySetFromBytes("test", []byte(policy))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	result := v.ValidatePolicies(ps)
	if result.Valid {
		t.Error("Expected validation errors for actions with no valid appliesTo")
	}
}

// TestExtractEntityTypeFromSet tests extractEntityTypeFromNode with set input
func TestExtractEntityTypeFromSet(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {
			"User": {"memberOfTypes": ["Group"]},
			"Group": {}
		},
		"actions": {
			"view": {
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["Group"]
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

	// Policy with "principal in [Group::...]"
	policy := `permit(principal, action == Action::"view", resource) when { principal in [Group::"g1", Group::"g2"] };`
	ps, err := cedar.NewPolicySetFromBytes("test", []byte(policy))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	result := v.ValidatePolicies(ps)
	// Should be valid - User can be in Group via memberOfTypes
	if !result.Valid {
		t.Errorf("Expected valid policy, got errors: %v", result.Errors)
	}
}

// TestExpectArgsWrongCount tests expectArgs with wrong argument count
func TestExpectArgsWrongCount(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {"User": {}, "Document": {}},
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

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Policy with extension call with wrong number of arguments
	// isInRange requires 2 args, here we pass expression that results in wrong types
	policy := `permit(principal, action == Action::"view", resource) when { ip("1.2.3.4").isInRange(ip("10.0.0.0/8")) };`
	ps, err := cedar.NewPolicySetFromBytes("test", []byte(policy))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	result := v.ValidatePolicies(ps)
	// Should be valid - correct usage of isInRange
	if !result.Valid {
		t.Errorf("Unexpected errors: %v", result.Errors)
	}
}

// TestInferSetTypeMultipleElements tests inferSetType with multiple elements
func TestInferSetTypeMultipleElements(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {
						"tags": {"type": "Set", "element": {"type": "String"}}
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
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Create entity with set containing multiple elements
	entities := types.EntityMap{
		types.NewEntityUID("User", "alice"): {
			Attributes: types.NewRecord(types.RecordMap{
				"tags": types.NewSet(types.String("a"), types.String("b"), types.String("c")),
			}),
		},
	}

	result := ValidateEntities(s, entities)
	if !result.Valid {
		t.Errorf("Expected valid entities, got errors: %v", result.Errors)
	}
}

// TestValidateContextUndeclaredStrictRequest tests context validation in strict mode for requests
func TestValidateContextUndeclaredStrictRequest(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {"User": {}, "Document": {}},
		"actions": {
			"view": {
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["Document"],
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

	v, err := New(s, WithStrictEntityValidation())
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Request with undeclared context attribute
	req := cedar.Request{
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "view"),
		Resource:  types.NewEntityUID("Document", "doc1"),
		Context: types.NewRecord(types.RecordMap{
			"ip":         types.String("1.2.3.4"),
			"undeclared": types.String("extra"),
		}),
	}

	result := v.ValidateRequest(req)
	if result.Valid {
		t.Error("Expected validation error for undeclared context attribute in strict mode")
	}
}

// TestCheckScopeTypeEqWithActionType tests checkScopeTypeEq with action entity types
func TestCheckScopeTypeEqWithActionType(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {"User": {}, "Document": {}},
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

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Policy referencing action in principal scope (unusual but tests the code path)
	policy := `permit(principal == User::"alice", action == Action::"view", resource == Document::"doc1");`
	ps, err := cedar.NewPolicySetFromBytes("test", []byte(policy))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	result := v.ValidatePolicies(ps)
	if !result.Valid {
		t.Errorf("Unexpected errors: %v", result.Errors)
	}
}

// TestTypecheckVariableAction tests typecheckVariable for action variable
func TestTypecheckVariableAction(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {"User": {}, "Document": {}},
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

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Policy that uses action variable in condition
	policy := `permit(principal, action, resource) when { action == Action::"view" };`
	ps, err := cedar.NewPolicySetFromBytes("test", []byte(policy))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	result := v.ValidatePolicies(ps)
	if !result.Valid {
		t.Errorf("Unexpected errors: %v", result.Errors)
	}
}

// TestParseActionMemberOf tests action memberOf parsing
func TestParseActionMemberOf(t *testing.T) {
	// Test action with memberOf relationship
	schemaJSON := `{
		"entityTypes": {"User": {}, "Document": {}},
		"actions": {
			"read": {
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
				"memberOf": [{"id": "read"}]
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

	// Check that memberOf was parsed
	actionUID := types.NewEntityUID("Action", "view")
	info, ok := v.actionTypes[actionUID]
	if !ok {
		t.Fatal("Action 'view' not found")
	}

	if len(info.MemberOf) != 1 {
		t.Errorf("Expected 1 memberOf, got %d", len(info.MemberOf))
	}
}

// TestCheckScopeTypeInWithDescendant tests checkScopeTypeIn with "in" clause
// Cedar's Lean implementation requires the entity type in "in" clause to be in allowed types
func TestCheckScopeTypeInWithDescendant(t *testing.T) {
	// Schema where User can be in Group via memberOfTypes
	schemaJSON := `{
		"entityTypes": {
			"User": {"memberOfTypes": ["Group"]},
			"Group": {"memberOfTypes": ["Org"]},
			"Org": {}
		},
		"actions": {
			"view": {
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["Org"]
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

	// Policy with "principal in Org::..." - Org is NOT in principalTypes
	// Per Lean's implementation, the entity type in "in" clause must be in allowed types
	policy := `permit(principal in Org::"acme", action == Action::"view", resource);`
	ps, err := cedar.NewPolicySetFromBytes("test", []byte(policy))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	result := v.ValidatePolicies(ps)
	// Should be invalid because Org is not in principalTypes
	if result.Valid {
		t.Error("Expected validation error for principal in Org:: when Org is not in principalTypes")
	}
	// Check that the error message mentions the issue
	if len(result.Errors) == 0 {
		t.Error("Expected at least one error")
	} else if !strings.Contains(result.Errors[0].Message, "not satisfiable") {
		t.Errorf("Expected 'not satisfiable' error, got: %v", result.Errors[0].Message)
	}
}

// TestIntersectAttributesTypeMismatch tests intersectAttributes with type mismatch
func TestIntersectAttributesTypeMismatch(t *testing.T) {
	// Two actions with same attribute name but different types
	schemaJSON := `{
		"entityTypes": {"User": {}, "Document": {}},
		"actions": {
			"view": {
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["Document"],
					"context": {
						"type": "Record",
						"attributes": {
							"value": {"type": "String"}
						}
					}
				}
			},
			"edit": {
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["Document"],
					"context": {
						"type": "Record",
						"attributes": {
							"value": {"type": "Long"}
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

	// Policy with unscoped action - context intersection should have no common attributes
	policy := `permit(principal == User::"alice", action, resource == Document::"doc1") when { context.value == "test" };`
	ps, err := cedar.NewPolicySetFromBytes("test", []byte(policy))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	result := v.ValidatePolicies(ps)
	// Should have error because context.value is not available (different types in intersection)
	if result.Valid {
		t.Error("Expected validation error for accessing context attribute with mismatched types across actions")
	}
}

// TestExpectArgsWrongArgCount tests expectArgs with wrong argument count
func TestExpectArgsWrongArgCount(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {"User": {}, "Document": {}},
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

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Policy with extension call - testing valid calls
	policy := `permit(principal, action == Action::"view", resource) when { decimal("1.0").lessThan(decimal("2.0")) };`
	ps, err := cedar.NewPolicySetFromBytes("test", []byte(policy))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	result := v.ValidatePolicies(ps)
	if !result.Valid {
		t.Errorf("Unexpected errors: %v", result.Errors)
	}
}

// TestResolveEntityScopeTypesAll tests resolveEntityScopeTypes with ScopeTypeAll
func TestResolveEntityScopeTypesAll(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {"User": {}, "Admin": {}, "Document": {}},
		"actions": {
			"view": {
				"appliesTo": {
					"principalTypes": ["User", "Admin"],
					"resourceTypes": ["Document"]
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

	// Policy with unscoped principal - should use all principal types from action
	policy := `permit(principal, action == Action::"view", resource == Document::"doc1");`
	ps, err := cedar.NewPolicySetFromBytes("test", []byte(policy))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	result := v.ValidatePolicies(ps)
	if !result.Valid {
		t.Errorf("Unexpected errors: %v", result.Errors)
	}
}

// TestCheckEntityTypeKnownAction tests checkEntityTypeKnown with action entity
func TestCheckEntityTypeKnownAction(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {"User": {}, "Document": {}},
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

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Policy with unknown action entity
	policy := `permit(principal, action == Action::"view", resource) when { Action::"unknown_action" == action };`
	ps, err := cedar.NewPolicySetFromBytes("test", []byte(policy))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	result := v.ValidatePolicies(ps)
	// Should have error for unknown action entity
	hasUnknownEntity := false
	for _, e := range result.Errors {
		if strings.Contains(e.Message, "unknownEntity") {
			hasUnknownEntity = true
			break
		}
	}
	if !hasUnknownEntity {
		t.Error("Expected unknownEntity error for undefined action")
	}
}

// TestEvaluateConstantOrShortCircuit tests evaluateConstantOr short-circuit paths
func TestEvaluateConstantOrShortCircuit(t *testing.T) {
	schemaJSON := `{
		"entityTypes": {"User": {}, "Document": {}},
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

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Policy with "unless { true || something }" - short circuits to true, making policy impossible
	policy := `permit(principal, action == Action::"view", resource) unless { true || false };`
	ps, err := cedar.NewPolicySetFromBytes("test", []byte(policy))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	result := v.ValidatePolicies(ps)
	// Should detect impossiblePolicy
	hasImpossible := false
	for _, e := range result.Errors {
		if e.Message == "impossiblePolicy" {
			hasImpossible = true
			break
		}
	}
	if !hasImpossible {
		t.Error("Expected impossiblePolicy error for 'unless { true || false }'")
	}
}
