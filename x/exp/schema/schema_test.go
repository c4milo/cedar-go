package schema

import (
	"encoding/json"
	"reflect"
	"strings"
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
			runCedarMarshalUnmarshalTest(t, tt.input, tt.wantErr)
		})
	}
}

func runCedarMarshalUnmarshalTest(t *testing.T, input string, wantErr bool) {
	t.Helper()
	s, err := NewFromCedar("test.cedar", []byte(input))
	if (err != nil) != wantErr {
		t.Fatalf("NewFromCedar() error = %v, wantErr %v", err, wantErr)
	}
	if wantErr {
		return
	}
	verifyCedarRoundTrip(t, s)
}

func verifyCedarRoundTrip(t *testing.T, s *Schema) {
	t.Helper()
	out, err := s.MarshalCedar()
	if err != nil {
		t.Fatalf("MarshalCedar() error = %v", err)
	}

	s2, err := NewFromCedar("test.cedar", out)
	if err != nil {
		t.Fatalf("NewFromCedar() second pass error = %v", err)
	}

	out2, err := s2.MarshalCedar()
	if err != nil {
		t.Fatalf("MarshalCedar() second pass error = %v", err)
	}

	if !reflect.DeepEqual(out, out2) {
		t.Errorf("Marshal/Unmarshal cycle produced different results:\nFirst: %s\nSecond: %s", out, out2)
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

func TestSchemaFragmentFromCedar(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name: "valid fragment with entity",
			input: `namespace users {
				entity User;
			}`,
			wantErr: false,
		},
		{
			name: "valid fragment with reference to undeclared type",
			input: `namespace users {
				entity User in [Organization];
			}`,
			wantErr: false, // Fragments allow undeclared references
		},
		{
			name:    "empty fragment",
			input:   "",
			wantErr: false,
		},
		{
			name: "invalid syntax",
			input: `namespace foo {
				invalid syntax
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frag, err := NewFragmentFromCedar("test.cedarschema", []byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFragmentFromCedar() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Test marshaling
			_, err = frag.MarshalCedar()
			if err != nil {
				t.Errorf("MarshalCedar() error = %v", err)
			}
		})
	}
}

func TestSchemaFragmentFromJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name: "valid JSON fragment with entityTypes",
			input: `{
				"entityTypes": {
					"User": {}
				}
			}`,
			wantErr: false,
		},
		{
			name: "namespace-based JSON fragment",
			input: `{
				"Users": {
					"entityTypes": {
						"User": {}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name:    "empty JSON fragment",
			input:   "{}",
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			input:   "{invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frag, err := NewFragmentFromJSON([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFragmentFromJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Test marshaling
			_, err = frag.MarshalJSON()
			if err != nil {
				t.Errorf("MarshalJSON() error = %v", err)
			}
		})
	}
}

func TestSchemaFragmentMerge(t *testing.T) {
	t.Run("merge non-overlapping namespaces", testMergeNonOverlappingNamespaces)
	t.Run("merge same namespace non-overlapping entities", testMergeSameNamespaceEntities)
	t.Run("merge conflict duplicate entity", testMergeConflictDuplicateEntity)
	t.Run("merge conflict duplicate action", testMergeConflictDuplicateAction)
	t.Run("merge conflict duplicate common type", testMergeConflictDuplicateCommonType)
	t.Run("merge with nil fragment", testMergeWithNilFragment)
}

func testMergeNonOverlappingNamespaces(t *testing.T) {
	frag1, _ := NewFragmentFromCedar("frag1.cedarschema", []byte(`namespace users { entity User; }`))
	frag2, _ := NewFragmentFromCedar("frag2.cedarschema", []byte(`namespace resources { entity Document; }`))

	merged, err := frag1.Merge(frag2)
	requireNoError(t, err, "Merge()")
	requireNamespaceExists(t, merged, "users")
	requireNamespaceExists(t, merged, "resources")
}

func testMergeSameNamespaceEntities(t *testing.T) {
	frag1, _ := NewFragmentFromCedar("frag1.cedarschema", []byte(`namespace app { entity User; }`))
	frag2, _ := NewFragmentFromCedar("frag2.cedarschema", []byte(`namespace app { entity Document; }`))

	merged, err := frag1.Merge(frag2)
	requireNoError(t, err, "Merge()")
	requireEntityExists(t, merged, "app", "User")
	requireEntityExists(t, merged, "app", "Document")
}

func testMergeConflictDuplicateEntity(t *testing.T) {
	frag1, _ := NewFragmentFromCedar("frag1.cedarschema", []byte(`namespace app { entity User; }`))
	frag2, _ := NewFragmentFromCedar("frag2.cedarschema", []byte(`namespace app { entity User; }`))

	_, err := frag1.Merge(frag2)
	requireError(t, err, "Merge() should return error for duplicate entity")
}

func testMergeConflictDuplicateAction(t *testing.T) {
	frag1, _ := NewFragmentFromCedar("frag1.cedarschema", []byte(`
		namespace app { entity User; action View appliesTo { principal: User, resource: User }; }`))
	frag2, _ := NewFragmentFromCedar("frag2.cedarschema", []byte(`
		namespace app { action View appliesTo { principal: User, resource: User }; }`))

	_, err := frag1.Merge(frag2)
	requireError(t, err, "Merge() should return error for duplicate action")
}

func testMergeConflictDuplicateCommonType(t *testing.T) {
	frag1, _ := NewFragmentFromJSON([]byte(`{"app": {"commonTypes": {"MyType": {"type": "String"}}}}`))
	frag2, _ := NewFragmentFromJSON([]byte(`{"app": {"commonTypes": {"MyType": {"type": "Long"}}}}`))

	_, err := frag1.Merge(frag2)
	requireError(t, err, "Merge() should return error for duplicate common type")
}

func testMergeWithNilFragment(t *testing.T) {
	frag1, _ := NewFragmentFromCedar("frag1.cedarschema", []byte(`namespace users { entity User; }`))
	merged, err := frag1.Merge(nil)
	requireNoError(t, err, "Merge() with nil")
	requireNamespaceExists(t, merged, "users")
}

func requireError(t *testing.T, err error, msg string) {
	t.Helper()
	if err == nil {
		t.Error(msg)
	}
}

func requireEntityExists(t *testing.T, frag *SchemaFragment, ns, entity string) {
	t.Helper()
	out, _ := frag.MarshalJSON()
	var result map[string]any
	_ = json.Unmarshal(out, &result)
	nsData, ok := result[ns].(map[string]any)
	if !ok {
		t.Errorf("namespace %q not found", ns)
		return
	}
	entityTypes, ok := nsData["entityTypes"].(map[string]any)
	if !ok {
		t.Errorf("entityTypes not found in namespace %q", ns)
		return
	}
	if _, ok := entityTypes[entity]; !ok {
		t.Errorf("entity %q not found in namespace %q", entity, ns)
	}
}

func TestFromFragments(t *testing.T) {
	t.Run("combine multiple fragments successfully", testFromFragmentsCombineMultiple)
	t.Run("empty fragments", testFromFragmentsEmpty)
	t.Run("duplicate type error", testFromFragmentsDuplicateType)
	t.Run("unresolved reference error", testFromFragmentsUnresolvedRef)
	t.Run("cross-fragment type reference", testFromFragmentsCrossRef)
	t.Run("action references entity from another fragment", testFromFragmentsActionRef)
}

func testFromFragmentsCombineMultiple(t *testing.T) {
	frag1, _ := NewFragmentFromCedar("common.cedarschema", []byte(`namespace common { entity Organization; }`))
	frag2, _ := NewFragmentFromCedar("users.cedarschema", []byte(`namespace users { entity User in [common::Organization]; }`))
	frag3, _ := NewFragmentFromJSON([]byte(`{"resources": {"entityTypes": {"Document": {}}}}`))

	schema, err := FromFragments(frag1, frag2, frag3)
	requireNoError(t, err, "FromFragments()")
	requireSchemaNamespaceExists(t, schema, "common")
	requireSchemaNamespaceExists(t, schema, "users")
	requireSchemaNamespaceExists(t, schema, "resources")
}

func testFromFragmentsEmpty(t *testing.T) {
	schema, err := FromFragments()
	requireNoError(t, err, "FromFragments()")
	out, _ := schema.MarshalJSON()
	if string(out) != "{}" {
		t.Errorf("expected empty schema, got %s", out)
	}
}

func testFromFragmentsDuplicateType(t *testing.T) {
	frag1, _ := NewFragmentFromCedar("frag1.cedarschema", []byte(`namespace app { entity User; }`))
	frag2, _ := NewFragmentFromCedar("frag2.cedarschema", []byte(`namespace app { entity User; }`))

	_, err := FromFragments(frag1, frag2)
	requireError(t, err, "FromFragments() should return error for duplicate types")
}

func testFromFragmentsUnresolvedRef(t *testing.T) {
	frag1, _ := NewFragmentFromCedar("frag1.cedarschema", []byte(`namespace users { entity User in [UndefinedType]; }`))
	_, err := FromFragments(frag1)
	requireError(t, err, "FromFragments() should return error for unresolved reference")
}

func testFromFragmentsCrossRef(t *testing.T) {
	frag1, _ := NewFragmentFromCedar("org.cedarschema", []byte(`namespace org { entity Organization; }`))
	frag2, _ := NewFragmentFromCedar("users.cedarschema", []byte(`namespace users { entity User in [org::Organization]; }`))

	schema, err := FromFragments(frag1, frag2)
	requireNoError(t, err, "FromFragments()")
	_, err = schema.MarshalCedar()
	requireNoError(t, err, "MarshalCedar()")
}

func testFromFragmentsActionRef(t *testing.T) {
	frag1, _ := NewFragmentFromCedar("entities.cedarschema", []byte(`namespace app { entity User; entity Document; }`))
	frag2, _ := NewFragmentFromCedar("actions.cedarschema", []byte(`namespace app { action View appliesTo { principal: User, resource: Document }; }`))

	schema, err := FromFragments(frag1, frag2)
	requireNoError(t, err, "FromFragments()")
	_, err = schema.MarshalCedar()
	requireNoError(t, err, "MarshalCedar()")
}

func requireSchemaNamespaceExists(t *testing.T, schema *Schema, ns string) {
	t.Helper()
	out, _ := schema.MarshalJSON()
	var result map[string]any
	_ = json.Unmarshal(out, &result)
	if _, ok := result[ns]; !ok {
		t.Errorf("schema missing %q namespace", ns)
	}
}

func TestFromFragmentsMixedFormats(t *testing.T) {
	t.Run("combine cedar and json fragments", func(t *testing.T) {
		cedarFrag, _ := NewFragmentFromCedar("entities.cedarschema", []byte(`
			namespace myapp {
				entity User;
			}
		`))

		jsonFrag, _ := NewFragmentFromJSON([]byte(`{
			"myapp": {
				"entityTypes": {
					"Document": {}
				},
				"actions": {
					"Read": {
						"appliesTo": {
							"principalTypes": ["User"],
							"resourceTypes": ["Document"]
						}
					}
				}
			}
		}`))

		schema, err := FromFragments(cedarFrag, jsonFrag)
		if err != nil {
			t.Fatalf("FromFragments() error = %v", err)
		}

		out, _ := schema.MarshalJSON()
		var result map[string]any
		_ = json.Unmarshal(out, &result)

		myapp := result["myapp"].(map[string]any)
		entityTypes := myapp["entityTypes"].(map[string]any)

		if _, ok := entityTypes["User"]; !ok {
			t.Error("merged schema missing 'User' entity")
		}
		if _, ok := entityTypes["Document"]; !ok {
			t.Error("merged schema missing 'Document' entity")
		}
	})
}

func TestFromFragmentsReferenceValidation(t *testing.T) {
	tests := []refValidationTest{
		{"unresolved memberOf reference", `{"app":{"entityTypes":{"User":{"memberOfTypes":["NonExistent"]}}}}`, "", true},
		{"valid memberOf reference", `{"app":{"entityTypes":{"User":{"memberOfTypes":["Group"]},"Group":{}}}}`, "", false},
		{"entity shape with self-reference", `{"app":{"entityTypes":{"User":{"shape":{"type":"Record","attributes":{"manager":{"type":"Entity","name":"User","required":true}}}}}}}`, "", false},
		{"entity shape with undefined reference", `{"app":{"entityTypes":{"User":{"shape":{"type":"Record","attributes":{"manager":{"type":"Entity","name":"NonExistent","required":true}}}}}}}`, "", true},
		{"entity shape with Set of entities", `{"app":{"entityTypes":{"User":{},"Group":{"shape":{"type":"Record","attributes":{"members":{"type":"Set","element":{"type":"Entity","name":"User"},"required":true}}}}}}}`, "", false},
		{"entity shape with Set of undefined", `{"app":{"entityTypes":{"Group":{"shape":{"type":"Record","attributes":{"members":{"type":"Set","element":{"type":"Entity","name":"Undefined"},"required":true}}}}}}}`, "", true},
		{"action context with entity reference", `{"app":{"entityTypes":{"User":{},"Document":{},"Session":{}},"actions":{"View":{"appliesTo":{"principalTypes":["User"],"resourceTypes":["Document"],"context":{"type":"Record","attributes":{"session":{"type":"Entity","name":"Session","required":true}}}}}}}}`, "", false},
		{"action context with undefined reference", `{"app":{"entityTypes":{"User":{},"Document":{}},"actions":{"View":{"appliesTo":{"principalTypes":["User"],"resourceTypes":["Document"],"context":{"type":"Record","attributes":{"session":{"type":"Entity","name":"Undefined","required":true}}}}}}}}`, "", true},
		{"common type with entity reference", `{"app":{"entityTypes":{"User":{}},"commonTypes":{"UserRef":{"type":"Entity","name":"User"}}}}`, "", false},
		{"common type with undefined reference", `{"app":{"commonTypes":{"UserRef":{"type":"Entity","name":"Undefined"}}}}`, "", true},
		{"entity tags validation", `{"app":{"entityTypes":{"User":{"tags":{"type":"Set","element":{"type":"String"}}}}}}`, "", false},
		{"primitive types in shapes", `{"app":{"entityTypes":{"User":{"shape":{"type":"Record","attributes":{"name":{"type":"String","required":true},"age":{"type":"Long","required":false}}}}}}}`, "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRefValidationTest(t, tc)
		})
	}

	t.Run("cross-namespace entity reference", testCrossNamespaceRef)
}

type refValidationTest struct {
	name      string
	json1     string
	json2     string
	wantError bool
}

func runRefValidationTest(t *testing.T, tc refValidationTest) {
	t.Helper()
	frag1, _ := NewFragmentFromJSON([]byte(tc.json1))
	frags := []*SchemaFragment{frag1}
	if tc.json2 != "" {
		frag2, _ := NewFragmentFromJSON([]byte(tc.json2))
		frags = append(frags, frag2)
	}

	_, err := FromFragments(frags...)
	if tc.wantError && err == nil {
		t.Error("expected error but got none")
	}
	if !tc.wantError && err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func testCrossNamespaceRef(t *testing.T) {
	frag1, _ := NewFragmentFromJSON([]byte(`{"org":{"entityTypes":{"Organization":{}}}}`))
	frag2, _ := NewFragmentFromJSON([]byte(`{"users":{"entityTypes":{"User":{"memberOfTypes":["org::Organization"]}}}}`))
	_, err := FromFragments(frag1, frag2)
	requireNoError(t, err, "FromFragments() for cross-namespace reference")
}

func TestSchemaFragmentMarshalEmpty(t *testing.T) {
	var f SchemaFragment
	_, err := f.MarshalCedar()
	if err == nil {
		t.Error("MarshalCedar() should return error for empty fragment")
	}

	out, err := f.MarshalJSON()
	if err != nil {
		t.Errorf("MarshalJSON() error = %v", err)
	}
	if out != nil {
		t.Errorf("MarshalJSON() should return nil for empty fragment, got %s", out)
	}
}

func TestMergeEdgeCases(t *testing.T) {
	t.Run("merge nil with nil", testMergeNilWithNil)
	t.Run("merge nil receiver with valid fragment", testMergeNilReceiverWithValid)
	t.Run("merge with empty jsonSchema receiver", testMergeEmptyReceiverSchema)
	t.Run("merge with empty jsonSchema other", testMergeEmptyOtherSchema)
}

func testMergeNilWithNil(t *testing.T) {
	var f *SchemaFragment
	merged, err := f.Merge(nil)
	requireNoError(t, err, "Merge()")
	requireNotNil(t, merged, "Merge() returned nil, expected empty fragment")
}

func testMergeNilReceiverWithValid(t *testing.T) {
	var f *SchemaFragment
	other, _ := NewFragmentFromJSON([]byte(`{"app": {"entityTypes": {"User": {}}}}`))
	merged, err := f.Merge(other)
	requireNoError(t, err, "Merge()")
	requireNamespaceExists(t, merged, "app")
}

func testMergeEmptyReceiverSchema(t *testing.T) {
	f := &SchemaFragment{jsonSchema: nil}
	other, _ := NewFragmentFromJSON([]byte(`{"app": {"entityTypes": {"User": {}}}}`))
	merged, err := f.Merge(other)
	requireNoError(t, err, "Merge()")
	requireNamespaceExists(t, merged, "app")
}

func testMergeEmptyOtherSchema(t *testing.T) {
	f, _ := NewFragmentFromJSON([]byte(`{"app": {"entityTypes": {"User": {}}}}`))
	other := &SchemaFragment{jsonSchema: nil}
	merged, err := f.Merge(other)
	requireNoError(t, err, "Merge()")
	requireNamespaceExists(t, merged, "app")
}

func requireNoError(t *testing.T, err error, context string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s error = %v", context, err)
	}
}

func requireNotNil(t *testing.T, v any, msg string) {
	t.Helper()
	if v == nil {
		t.Fatal(msg)
	}
}

func requireNamespaceExists(t *testing.T, frag *SchemaFragment, ns string) {
	t.Helper()
	out, _ := frag.MarshalJSON()
	var result map[string]any
	_ = json.Unmarshal(out, &result)
	if _, ok := result[ns]; !ok {
		t.Errorf("merged fragment missing %q namespace", ns)
	}
}

func TestFromFragmentsEdgeCases(t *testing.T) {
	t.Run("single nil fragment", func(t *testing.T) {
		schema, err := FromFragments(nil)
		if err != nil {
			t.Errorf("FromFragments() error = %v", err)
		}
		if schema == nil {
			t.Error("FromFragments() returned nil schema")
		}
	})

	t.Run("fragments with nil namespace entry", func(t *testing.T) {
		frag, _ := NewFragmentFromJSON([]byte(`{}`))

		schema, err := FromFragments(frag)
		if err != nil {
			t.Errorf("FromFragments() error = %v", err)
		}
		if schema == nil {
			t.Error("FromFragments() returned nil schema")
		}
	})

	t.Run("action with nil appliesTo", func(t *testing.T) {
		frag, _ := NewFragmentFromJSON([]byte(`{
			"app": {
				"entityTypes": {},
				"actions": {
					"DoSomething": {}
				}
			}
		}`))

		schema, err := FromFragments(frag)
		if err != nil {
			t.Errorf("FromFragments() error = %v", err)
		}
		if schema == nil {
			t.Error("FromFragments() returned nil schema")
		}
	})

	t.Run("entity with nil entity definition", func(t *testing.T) {
		frag, _ := NewFragmentFromJSON([]byte(`{
			"app": {
				"entityTypes": {
					"User": null
				}
			}
		}`))

		_, err := FromFragments(frag)
		// Should not panic, handles nil gracefully
		if err != nil {
			t.Logf("FromFragments() error = %v (expected for nil entity)", err)
		}
	})
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

func TestInvalidIdentifiers(t *testing.T) {
	// Only entity type names, common type names, and namespace names must be valid identifiers.
	// Record attribute names can be any string (they're quoted in Cedar syntax).
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "invalid entity type starting with digit",
			input:   `{"entityTypes": {"000": {}}}`,
			wantErr: true,
			errMsg:  "invalid entity type identifier",
		},
		{
			name:    "invalid common type starting with digit",
			input:   `{"commonTypes": {"123type": {"type": "Long"}}}`,
			wantErr: true,
			errMsg:  "invalid common type identifier",
		},
		{
			name:    "invalid namespace starting with digit",
			input:   `{"123ns": {"entityTypes": {"User": {}}}}`,
			wantErr: true,
			errMsg:  "invalid namespace identifier",
		},
		{
			name:    "attribute name starting with digit is VALID",
			input:   `{"entityTypes": {"User": {"shape": {"type": "Record", "attributes": {"123attr": {"type": "String", "required": true}}}}}}`,
			wantErr: false, // Attribute names can be any string - they're quoted in Cedar syntax
		},
		{
			name:    "attribute name with special chars is VALID",
			input:   `{"entityTypes": {"User": {"shape": {"type": "Record", "attributes": {"a-b-c": {"type": "String", "required": true}}}}}}`,
			wantErr: false, // Attribute names can be any string
		},
		{
			name:    "valid identifiers",
			input:   `{"entityTypes": {"User": {"shape": {"type": "Record", "attributes": {"name": {"type": "String", "required": true}}}}}}`,
			wantErr: false,
		},
		{
			name:    "valid identifier with underscore prefix",
			input:   `{"entityTypes": {"_User": {}}}`,
			wantErr: false,
		},
		{
			name:    "valid identifier with digits",
			input:   `{"entityTypes": {"User123": {}}}`,
			wantErr: false,
		},
		{
			name:    "empty entity type name",
			input:   `{"entityTypes": {"": {}}}`,
			wantErr: true,
			errMsg:  "invalid entity type identifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewFromJSON([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFromJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing %q, got: %v", tt.errMsg, err)
				}
			}
		})
	}
}

// TestEntityOrCommonTypeReference tests validation of EntityOrCommon type references
func TestEntityOrCommonTypeReference(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid entity reference in set element",
			input: `{
				"entityTypes": {
					"User": {},
					"Group": {
						"shape": {
							"type": "Record",
							"attributes": {
								"members": {
									"type": "Set",
									"element": {"type": "EntityOrCommon", "name": "User"}
								}
							}
						}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "valid qualified entity reference",
			input: `{
				"MyNs": {
					"entityTypes": {
						"User": {},
						"Group": {
							"shape": {
								"type": "Record",
								"attributes": {
									"owner": {"type": "EntityOrCommon", "name": "MyNs::User"}
								}
							}
						}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "invalid entity reference with bad identifier",
			input: `{
				"entityTypes": {
					"User": {
						"shape": {
							"type": "Record",
							"attributes": {
								"ref": {"type": "EntityOrCommon", "name": "123Invalid"}
							}
						}
					}
				}
			}`,
			wantErr: true,
			errMsg:  "invalid identifier",
		},
		{
			name: "invalid qualified reference with bad part",
			input: `{
				"entityTypes": {
					"User": {
						"shape": {
							"type": "Record",
							"attributes": {
								"ref": {"type": "EntityOrCommon", "name": "Valid::123Invalid"}
							}
						}
					}
				}
			}`,
			wantErr: true,
			errMsg:  "invalid identifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewFromJSON([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFromJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing %q, got: %v", tt.errMsg, err)
				}
			}
		})
	}
}

// TestSetTypeReferences tests validation of Set type references
func TestSetTypeReferences(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name: "valid set of strings",
			input: `{
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
			name: "valid nested set",
			input: `{
				"entityTypes": {
					"User": {
						"shape": {
							"type": "Record",
							"attributes": {
								"nestedTags": {"type": "Set", "element": {"type": "Set", "element": {"type": "String"}}}
							}
						}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "set with entity reference",
			input: `{
				"entityTypes": {
					"User": {},
					"Group": {
						"shape": {
							"type": "Record",
							"attributes": {
								"members": {"type": "Set", "element": {"type": "Entity", "name": "User"}}
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
			_, err := NewFromJSON([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFromJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestPrimitiveTypeValidation tests validation of primitive type names
func TestPrimitiveTypeValidation(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "String type",
			input:   `{"entityTypes": {"User": {"shape": {"type": "Record", "attributes": {"name": {"type": "String"}}}}}}`,
			wantErr: false,
		},
		{
			name:    "Long type",
			input:   `{"entityTypes": {"User": {"shape": {"type": "Record", "attributes": {"age": {"type": "Long"}}}}}}`,
			wantErr: false,
		},
		{
			name:    "Boolean type",
			input:   `{"entityTypes": {"User": {"shape": {"type": "Record", "attributes": {"active": {"type": "Boolean"}}}}}}`,
			wantErr: false,
		},
		{
			name:    "Bool type (alias)",
			input:   `{"entityTypes": {"User": {"shape": {"type": "Record", "attributes": {"active": {"type": "Bool"}}}}}}`,
			wantErr: false,
		},
		{
			name:    "Extension type (decimal)",
			input:   `{"entityTypes": {"User": {"shape": {"type": "Record", "attributes": {"score": {"type": "Extension", "name": "decimal"}}}}}}`,
			wantErr: false,
		},
		{
			name:    "Extension type (ipaddr)",
			input:   `{"entityTypes": {"User": {"shape": {"type": "Record", "attributes": {"ip": {"type": "Extension", "name": "ipaddr"}}}}}}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewFromJSON([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFromJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCommonTypeReferences tests validation of common type references
func TestCommonTypeReferences(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid common type reference",
			input: `{
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
								"homeAddress": {"type": "Address"}
							}
						}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "common type with nested record",
			input: `{
				"commonTypes": {
					"ContactInfo": {
						"type": "Record",
						"attributes": {
							"email": {"type": "String"},
							"phone": {"type": "String"}
						}
					}
				},
				"entityTypes": {
					"User": {
						"shape": {
							"type": "Record",
							"attributes": {
								"contact": {"type": "ContactInfo"}
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
			_, err := NewFromJSON([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFromJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing %q, got: %v", tt.errMsg, err)
				}
			}
		})
	}
}

// TestActionAppliesToValidation tests validation of action appliesTo parsing
func TestActionAppliesToValidation(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name: "valid appliesTo",
			input: `{
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
			}`,
			wantErr: false,
		},
		{
			name: "appliesTo with context type",
			input: `{
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
									"ip": {"type": "String"}
								}
							}
						}
					}
				}
			}`,
			wantErr: false,
		},
		{
			name: "action with memberOf",
			input: `{
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
					},
					"admin": {
						"memberOf": [{"id": "view"}],
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
			name: "multiple actions",
			input: `{
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
					},
					"edit": {
						"appliesTo": {
							"principalTypes": ["User"],
							"resourceTypes": ["Document"]
						}
					},
					"delete": {
						"appliesTo": {
							"principalTypes": ["User"],
							"resourceTypes": ["Document"]
						}
					}
				}
			}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewFromJSON([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFromJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCedarFormatParsing tests parsing Cedar format schemas
func TestCedarFormatParsing(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name: "simple Cedar schema",
			input: `entity User;
entity Document;
action view appliesTo { principal: User, resource: Document };`,
			wantErr: false,
		},
		{
			name: "Cedar schema with attributes",
			input: `entity User {
  name: String,
  age: Long,
};
entity Document;
action view appliesTo { principal: User, resource: Document };`,
			wantErr: false,
		},
		{
			name: "Cedar schema with namespace",
			input: `namespace MyApp {
  entity User;
  entity Document;
  action view appliesTo { principal: User, resource: Document };
}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewFromCedar("test.cedarschema", []byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFromCedar() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
