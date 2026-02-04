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

	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
)

// Entity validation tests.

func TestValidateEntities(t *testing.T) {

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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "alice"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"name": types.String("Alice"),
			}),
		},
	}

	result := ValidateEntities(s, entities)
	if !result.Valid {
		t.Errorf("Expected valid entities, got errors: %v", result.Errors)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
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
						"age":    types.String("not a number"),
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
					Parents: types.NewEntityUIDSet(types.NewEntityUID("Document", "doc1")),
				},
			},
			expectValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ValidateEntities(s, tc.entities)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
			if !tc.expectValid && result.Valid {
				t.Error("Expected invalid, but validation passed")
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
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
			result := ValidateEntities(s, tc.entities)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got errors: %v", result.Errors)
			}
		})
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	entities := types.EntityMap{
		types.EntityUID{Type: "UnknownType", ID: "test"}: types.Entity{},
	}

	result := ValidateEntities(s, entities)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"name": types.Long(42),
			}),
		},
	}

	result := ValidateEntities(s, entities)
	if result.Valid {
		t.Error("Expected invalid for entity with wrong attribute type")
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{}),
		},
	}

	result := ValidateEntities(s, entities)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"roles": types.NewSet(types.String("admin"), types.String("user")),
			}),
		},
	}

	result := ValidateEntities(s, entities)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}

	entities = types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"roles": types.NewSet(types.Long(1), types.Long(2)),
			}),
		},
	}

	result = ValidateEntities(s, entities)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"profile": types.NewRecord(types.RecordMap{
					"bio": types.String("Hello"),
				}),
			}),
		},
	}

	result := ValidateEntities(s, entities)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}

	entities = types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"profile": types.String("not a record"),
			}),
		},
	}

	result = ValidateEntities(s, entities)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"manager": types.EntityUID{Type: "User", ID: "boss"},
			}),
		},
	}

	result := ValidateEntities(s, entities)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}

	entities = types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"manager": types.EntityUID{Type: "WrongType", ID: "boss"},
			}),
		},
	}

	result = ValidateEntities(s, entities)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	ip, _ := types.ParseIPAddr("192.168.1.1")
	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"ip": ip,
			}),
		},
	}

	result := ValidateEntities(s, entities)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	entities := types.EntityMap{
		types.EntityUID{Type: "Action", ID: "view"}: types.Entity{},
	}

	result := ValidateEntities(s, entities)
	if !result.Valid {
		t.Errorf("Expected valid for Action entity, got errors: %v", result.Errors)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "alice"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"name":       types.String("Alice"),
				"extraField": types.String("should not be here"),
			}),
		},
	}

	result := ValidateEntities(s, entities)
	if !result.Valid {
		t.Errorf("Without strict mode, extra attributes should be allowed, got errors: %v", result.Errors)
	}

	result = ValidateEntities(s, entities, WithStrictEntityValidation())
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
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
			result := ValidateEntities(s, tc.entities)
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
