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
		// Verify isCedarType() doesn't panic (it's a marker method)
		ct.isCedarType()

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
