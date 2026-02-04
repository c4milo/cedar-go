package schema

import (
	"encoding/json"
	"reflect"
	"sync"
	"testing"
)

func TestSchemaCedarMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name: "valid schema",
			input: `namespace foo {
				entity User;
				action Bar appliesTo {
					principal: User,
					resource: User
				};
			}`,
			wantErr: false,
		},
		{
			name:    "empty schema",
			input:   "",
			wantErr: false,
		},
		{
			name: "invalid schema",
			input: `namespace foo {
				action Bar = {
					invalid syntax here
				};
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewFromCedar("test.cedar", []byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFromCedar() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Test marshaling
			out, err := s.MarshalCedar()
			if err != nil {
				t.Errorf("MarshalCedar() error = %v", err)
				return
			}

			// For valid schemas, unmarshaling and marshaling should preserve content
			s2, err := NewFromCedar("test.cedar", out)
			if err != nil {
				t.Errorf("NewFromCedar() second pass error = %v", err)
				return
			}

			out2, err := s2.MarshalCedar()
			if err != nil {
				t.Errorf("MarshalCedar() second pass error = %v", err)
				return
			}

			if !reflect.DeepEqual(out, out2) {
				t.Errorf("Marshal/Unmarshal cycle produced different results:\nFirst: %s\nSecond: %s", out, out2)
			}
		})
	}
}

func TestSchemaCedarMarshalEmpty(t *testing.T) {
	var s Schema
	_, err := s.MarshalCedar()
	if err == nil {
		t.Errorf("MarshalCedar() should return an error for empty schema")
	}
}

func TestSchemaJSONMarshalEmpty(t *testing.T) {
	var s Schema
	out, err := s.MarshalJSON()
	if err != nil {
		t.Errorf("MarshalJSON() error = %v", err)
		return
	}
	if len(out) != 0 {
		t.Errorf("MarshalJSON() produced non-empty output for empty schema")
	}
}

func TestSchemaJSONMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name: "valid JSON schema",
			input: `{
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
			name:    "empty JSON",
			input:   "{}",
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			input:   "{invalid json",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewFromJSON([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFromJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Test marshaling
			out, err := s.MarshalJSON()
			if err != nil {
				t.Errorf("MarshalJSON() error = %v", err)
				return
			}

			// Verify JSON validity
			var raw any
			if err := json.Unmarshal(out, &raw); err != nil {
				t.Errorf("MarshalJSON() produced invalid JSON: %v", err)
			}
		})
	}
}

func TestSchemaCrossFormatMarshaling(t *testing.T) {
	t.Run("JSON to Cedar Marshalling", func(t *testing.T) {
		s, err := NewFromJSON([]byte(`{}`))
		if err != nil {
			t.Fatalf("NewFromJSON() error = %v", err)
		}

		_, err = s.MarshalCedar()
		if err != nil {
			t.Error("MarshalCedar() should not return error after NewFromJSON")
		}
	})

	t.Run("Cedar to JSON marshaling allowed", func(t *testing.T) {
		s, err := NewFromCedar("test.cedar", []byte(`namespace test {}`))
		if err != nil {
			t.Fatalf("NewFromCedar() error = %v", err)
		}

		_, err = s.MarshalJSON()
		if err != nil {
			t.Errorf("MarshalJSON() error = %v", err)
		}
	})
}

func TestSchemaConcurrentAccess(t *testing.T) {
	t.Parallel()

	s, err := NewFromJSON([]byte(`{
		"": {
			"entityTypes": {
				"User": {}
			},
			"actions": {}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}

	// Concurrent reads should be safe (no mutex needed - fully immutable)
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = s.MarshalJSON()
		}()
		go func() {
			defer wg.Done()
			_, _ = s.MarshalCedar()
		}()
	}
	wg.Wait()
}

func TestNewFromJSONFlatSchema(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name: "flat schema with entityTypes",
			input: `{
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
			name: "flat schema with actions",
			input: `{
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
			input: `{
				"commonTypes": {
					"MyString": {"type": "String"}
				}
			}`,
			wantErr: false,
		},
		{
			name: "flat schema with all top-level keys",
			input: `{
				"entityTypes": {"User": {}},
				"actions": {"view": {}},
				"commonTypes": {"MyType": {"type": "Long"}}
			}`,
			wantErr: false,
		},
		{
			name: "namespace-based schema",
			input: `{
				"MyNamespace": {
					"entityTypes": {"User": {}},
					"actions": {"view": {}}
				}
			}`,
			wantErr: false,
		},
		{
			name:    "invalid flat schema JSON",
			input:   `{"entityTypes": invalid}`,
			wantErr: true,
		},
		{
			name:    "completely invalid JSON",
			input:   `not json at all`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewFromJSON([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFromJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify we can marshal back to JSON
			out, err := s.MarshalJSON()
			if err != nil {
				t.Errorf("MarshalJSON() error = %v", err)
				return
			}

			// Verify output is valid JSON
			var raw any
			if err := json.Unmarshal(out, &raw); err != nil {
				t.Errorf("MarshalJSON() produced invalid JSON: %v", err)
			}
		})
	}
}
