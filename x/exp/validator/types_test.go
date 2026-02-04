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

// Type system tests.

func TestTypesMatch(t *testing.T) {
	tests := []struct {
		name     string
		expected CedarType
		actual   CedarType
		want     bool
	}{
		{"bool match", BoolType{}, BoolType{}, true},
		{"long match", LongType{}, LongType{}, true},
		{"string match", StringType{}, StringType{}, true},
		{"bool vs long", BoolType{}, LongType{}, false},
		{"entity match", EntityType{Name: "User"}, EntityType{Name: "User"}, true},
		{"entity mismatch", EntityType{Name: "User"}, EntityType{Name: "Admin"}, false},
		{"set match", SetType{Element: StringType{}}, SetType{Element: StringType{}}, true},
		{"extension match", ExtensionType{Name: "decimal"}, ExtensionType{Name: "decimal"}, true},
		{"extension mismatch", ExtensionType{Name: "decimal"}, ExtensionType{Name: "ipaddr"}, false},
		{"unknown expected matches anything", UnknownType{}, BoolType{}, true},
		{"unknown actual matches anything", StringType{}, UnknownType{}, false},
		{"any entity matches entity", AnyEntityType{}, EntityType{Name: "User"}, true},
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

func TestCedarTypeStrings(t *testing.T) {
	tests := []struct {
		typ  CedarType
		want string
	}{
		{BoolType{}, "Bool"},
		{LongType{}, "Long"},
		{StringType{}, "String"},
		{EntityType{Name: "User"}, "Entity<User>"},
		{SetType{Element: StringType{}}, "Set<String>"},
		{ExtensionType{Name: "decimal"}, "decimal"},
		{UnknownType{}, "Unknown"},
		{AnyEntityType{}, "Entity"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			got := tc.typ.String()
			if got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRecordTypeString(t *testing.T) {
	rt := RecordType{
		Attributes: map[string]AttributeType{
			"name": {Type: StringType{}, Required: true},
		},
	}
	got := rt.String()
	if got != "Record" {
		t.Errorf("String() = %q, want %q", got, "Record")
	}
}

func TestTypesMatchAdditional(t *testing.T) {
	tests := []struct {
		name     string
		expected CedarType
		actual   CedarType
		want     bool
	}{

		{"entity expected, any entity actual", EntityType{Name: "User"}, AnyEntityType{}, true},
		{"entity expected, non-entity actual", EntityType{Name: "User"}, StringType{}, false},

		{"any entity expected, entity actual", AnyEntityType{}, EntityType{Name: "User"}, true},
		{"any entity expected, any entity actual", AnyEntityType{}, AnyEntityType{}, true},
		{"any entity expected, non-entity actual", AnyEntityType{}, StringType{}, false},
		{"any entity expected, long actual", AnyEntityType{}, LongType{}, false},

		{"set mismatch element", SetType{Element: StringType{}}, SetType{Element: LongType{}}, false},
		{"set expected, non-set actual", SetType{Element: StringType{}}, LongType{}, false},

		{"record expected, non-record actual", RecordType{}, StringType{}, false},

		{"extension expected, non-extension actual", ExtensionType{Name: "decimal"}, StringType{}, false},

		{"default type", RecordType{}, RecordType{}, true},
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

func TestInferTypeWithAllExtensions(t *testing.T) {
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

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	decimal, _ := types.ParseDecimal("10.5")
	datetime, _ := types.ParseDatetime("2024-01-01")
	duration, _ := types.ParseDuration("1h")

	tests := []struct {
		name     string
		value    types.Value
		expected string
	}{
		{"decimal", decimal, "decimal"},
		{"datetime", datetime, "datetime"},
		{"duration", duration, "duration"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inferred := v.inferType(tc.value)
			ext, ok := inferred.(ExtensionType)
			if !ok {
				t.Errorf("Expected ExtensionType, got %T", inferred)
				return
			}
			if ext.Name != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, ext.Name)
			}
		})
	}
}

func TestInferSetTypeEdgeCases(t *testing.T) {
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

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	emptySet := types.NewSet()
	inferred := v.inferType(emptySet)
	setType, ok := inferred.(SetType)
	if !ok {
		t.Fatalf("Expected SetType, got %T", inferred)
	}
	_, isUnknown := setType.Element.(UnknownType)
	if !isUnknown {
		t.Errorf("Expected UnknownType element for empty set, got %T", setType.Element)
	}
}

func TestTypeInListWithNonEmptyList(t *testing.T) {
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

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	list := []types.EntityType{"User", "Admin"}
	if !v.typeInList("User", list) {
		t.Error("Expected User to be in list")
	}

	if v.typeInList("Guest", list) {
		t.Error("Expected Guest to not be in list")
	}

	if !v.typeInList("Anything", nil) {
		t.Error("Expected any type to be allowed with empty list")
	}
}

func TestUnifyTypes(t *testing.T) {

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
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { if true then 1 else 2 > 0 };`)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("test", &policy)

	result := ValidatePolicies(s, policies)
	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
}

func TestInferTypeUnknown(t *testing.T) {
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

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	inferred := v.inferType(nil)

	if inferred == nil {
		t.Error("Expected non-nil type")
	}
}

func TestIsCedarTypeMethods(t *testing.T) {

	types := []CedarType{
		BoolType{},
		LongType{},
		StringType{},
		EntityType{Name: "User"},
		SetType{Element: StringType{}},
		RecordType{},
		ExtensionType{Name: "decimal"},
		AnyEntityType{},
		UnknownType{},
	}

	for _, ct := range types {

		ct.isCedarType()
		_ = ct.String()
	}
}

// TestSetTypeInference tests type inference for set operations.
func TestSetTypeInference(t *testing.T) {
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
			name:        "set contains check",
			policy:      `permit(principal == User::"alice", action == Action::"view", resource) when { principal.roles.contains("admin") };`,
			expectValid: true,
		},
		{
			name:        "empty set literal",
			policy:      `permit(principal, action, resource) when { [].isEmpty() };`,
			expectValid: true,
		},
		{
			name:        "set literal with elements",
			policy:      `permit(principal, action, resource) when { ["a", "b"].contains("a") };`,
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

// TestRecordLiteralTypeInference tests type inference for record literals.
func TestRecordLiteralTypeInference(t *testing.T) {
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
		name        string
		policy      string
		expectValid bool
	}{
		{
			name:        "record literal in condition",
			policy:      `permit(principal, action, resource) when { {name: "test"}.name == "test" };`,
			expectValid: true,
		},
		{
			name:        "nested record literal",
			policy:      `permit(principal, action, resource) when { {outer: {inner: "value"}}.outer.inner == "value" };`,
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

// TestNestedRecordTypes tests nested record types in schema.
func TestNestedRecordTypes(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"address": {
								"type": "Record",
								"attributes": {
									"street": {"type": "String"},
									"city": {"type": "String"},
									"zip": {"type": "Long"}
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

	v, err := New(s)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	userInfo, ok := v.entityTypes["User"]
	if !ok {
		t.Fatal("User entity type not found")
	}

	addressAttr, ok := userInfo.Attributes["address"]
	if !ok {
		t.Fatal("address attribute not found")
	}

	recordType, ok := addressAttr.Type.(RecordType)
	if !ok {
		t.Fatalf("Expected address to be RecordType, got %T", addressAttr.Type)
	}

	if _, ok := recordType.Attributes["street"]; !ok {
		t.Error("Expected address to have 'street' attribute")
	}
	if _, ok := recordType.Attributes["city"]; !ok {
		t.Error("Expected address to have 'city' attribute")
	}
	if _, ok := recordType.Attributes["zip"]; !ok {
		t.Error("Expected address to have 'zip' attribute")
	}
}

// TestInferTypeFromValue tests type inference from Cedar values.
func TestInferTypeFromValue(t *testing.T) {
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
		name         string
		value        types.Value
		expectedType string
	}{
		{"boolean true", types.Boolean(true), "Bool"},
		{"boolean false", types.Boolean(false), "Bool"},
		{"long", types.Long(42), "Long"},
		{"string", types.String("hello"), "String"},
		{"entity", types.EntityUID{Type: "User", ID: "alice"}, "Entity<User>"},
		{"empty set", types.NewSet(), "Set<Unknown>"},
		{"set with elements", types.NewSet(types.String("a")), "Set<String>"},
		{"record", types.NewRecord(types.RecordMap{"key": types.String("value")}), "Record"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inferredType := v.inferType(tc.value)
			if inferredType.String() != tc.expectedType {
				t.Errorf("Expected %s, got %s", tc.expectedType, inferredType.String())
			}
		})
	}
}
