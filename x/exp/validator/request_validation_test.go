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

// Request and context validation tests.

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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	result := ValidateRequest(s, req)
	if !result.Valid {
		t.Errorf("Expected valid request, got error: %s", result.Error)
	}

	badReq := cedar.Request{
		Principal: types.EntityUID{Type: "Admin", ID: "bob"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	result = ValidateRequest(s, badReq)
	if result.Valid {
		t.Error("Expected invalid request for wrong principal type")
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
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
			result := ValidateRequest(s, req)
			if tc.expectValid && !result.Valid {
				t.Errorf("Expected valid, got error: %s", result.Error)
			}
			if !tc.expectValid && result.Valid {
				t.Error("Expected invalid, but validation passed")
			}
		})
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context: types.NewRecord(types.RecordMap{
			"authenticated": types.True,
		}),
	}

	result := ValidateRequest(s, req)
	if !result.Valid {
		t.Errorf("Expected valid request, got error: %s", result.Error)
	}

	badReq := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context: types.NewRecord(types.RecordMap{
			"authenticated": types.String("yes"),
		}),
	}

	result = ValidateRequest(s, badReq)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "unknown"},
		Resource:  types.EntityUID{Type: "User", ID: "bob"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	result := ValidateRequest(s, req)
	if result.Valid {
		t.Error("Expected invalid request for unknown action")
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Folder", ID: "folder1"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	result := ValidateRequest(s, req)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	err = v.validateContext(types.String("not a record"), schema.RecordType{})
	if err == nil {
		t.Error("Expected error for non-record context")
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context: types.NewRecord(types.RecordMap{
			"ip": types.String("127.0.0.1"),
		}),
	}

	result := ValidateRequest(s, req)
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context: types.NewRecord(types.RecordMap{
			"count": types.String("not a number"),
		}),
	}

	result := ValidateRequest(s, req)
	if result.Valid {
		t.Error("Expected invalid request for wrong context attribute type")
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

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	validReq := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context:   types.NewRecord(types.RecordMap{"ip": types.String("192.168.1.1")}),
	}

	result := ValidateRequest(s, validReq)
	if !result.Valid {
		t.Errorf("Expected valid request, got error: %s", result.Error)
	}

	invalidReq := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	result = ValidateRequest(s, invalidReq)
	if result.Valid {
		t.Error("Expected invalid request for missing required context")
	}
}
