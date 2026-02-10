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

// Schema parsing tests.

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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	result := ValidatePolicies(s, cedar.NewPolicySet())
	if !result.Valid {
		t.Errorf("Expected valid policies, got errors: %v", result.Errors)
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
						"lat": {"type": "Long", "required": true},
						"lon": {"type": "Long", "required": true}
					}
				}
			},
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"email": {"type": "EmailAddress", "required": true},
							"location": {"type": "Coordinate", "required": true}
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
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.email == "test@example.com" };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { context.authenticated };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	result := ValidatePolicies(s, cedar.NewPolicySet())
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
							"manager": {"type": "Entity", "name": "User", "required": true},
							"anyEntity": {"type": "Entity", "required": true}
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
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.manager == User::"bob" };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
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
							"roles": {"type": "Set", "element": {"type": "String"}, "required": true},
							"anySet": {"type": "Set", "required": true}
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
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.roles.contains("admin") };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal in Group::"admins" };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
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

func TestValidatePoliciesWithNilSchema(t *testing.T) {
	result := ValidatePolicies(nil, cedar.NewPolicySet())
	if result.Valid {
		t.Error("Expected invalid for nil schema")
	}
	if len(result.Errors) == 0 {
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

func TestSchemaWithTypeBoolean(t *testing.T) {

	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"active": {"type": "Bool", "required": true}
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
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.active };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestSchemaWithTopLevelContext(t *testing.T) {

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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	result := ValidatePolicies(s, cedar.NewPolicySet())
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestSchemaWithNullNamespace(t *testing.T) {

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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	_, err = New(s)
	if err != nil {
		t.Errorf("Expected success with null namespace, got error: %v", err)
	}
}

func TestSchemaParserCoverage(t *testing.T) {

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
			s, err := schema.NewFromJSON([]byte(tc.schemaJSON))
			if err != nil {
				t.Fatalf("Failed to parse schema: %v", err)
			}

			_, err = New(s)
			if tc.wantErr && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Expected no error, got: %v", err)
			}
		})
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
			s, err := schema.NewFromJSON([]byte(tc.schemaJSON))
			if tc.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected schema parse error: %v", err)
			}

			_, err = New(s)
			if err != nil {
				t.Errorf("Unexpected validator creation error: %v", err)
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
		extType, ok := attr.Type.(schema.ExtensionType)
		if !ok {
			t.Errorf("Expected attribute %s to be ExtensionType, got %T", attrName, attr.Type)
			continue
		}
		if extType.Name != expectedTypeName {
			t.Errorf("Expected attribute %s to have extension type %s, got %s", attrName, expectedTypeName, extType.Name)
		}
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

	tagsAttr, ok := userInfo.Attributes["tags"]
	if !ok {
		t.Fatal("tags attribute not found")
	}
	if setType, ok := tagsAttr.Type.(schema.SetType); ok {
		if _, ok := setType.Element.(schema.StringType); !ok {
			t.Errorf("Expected tags element to be StringType, got %T", setType.Element)
		}
	} else {
		t.Errorf("Expected tags to be SetType, got %T", tagsAttr.Type)
	}

	scoresAttr, ok := userInfo.Attributes["scores"]
	if !ok {
		t.Fatal("scores attribute not found")
	}
	if setType, ok := scoresAttr.Type.(schema.SetType); ok {
		if _, ok := setType.Element.(schema.LongType); !ok {
			t.Errorf("Expected scores element to be LongType, got %T", setType.Element)
		}
	} else {
		t.Errorf("Expected scores to be SetType, got %T", scoresAttr.Type)
	}
}
