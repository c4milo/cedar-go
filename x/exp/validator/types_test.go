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
		expected schema.CedarType
		actual   schema.CedarType
		want     bool
	}{
		{"bool match", schema.BoolType{}, schema.BoolType{}, true},
		{"long match", schema.LongType{}, schema.LongType{}, true},
		{"string match", schema.StringType{}, schema.StringType{}, true},
		{"bool vs long", schema.BoolType{}, schema.LongType{}, false},
		{"entity match", schema.EntityCedarType{Name: "User"}, schema.EntityCedarType{Name: "User"}, true},
		{"entity mismatch", schema.EntityCedarType{Name: "User"}, schema.EntityCedarType{Name: "Admin"}, false},
		{"set match", schema.SetType{Element: schema.StringType{}}, schema.SetType{Element: schema.StringType{}}, true},
		{"extension match", schema.ExtensionType{Name: "decimal"}, schema.ExtensionType{Name: "decimal"}, true},
		{"extension mismatch", schema.ExtensionType{Name: "decimal"}, schema.ExtensionType{Name: "ipaddr"}, false},
		{"unknown expected matches anything", schema.UnknownType{}, schema.BoolType{}, true},
		{"unknown actual matches anything", schema.StringType{}, schema.UnknownType{}, false},
		{"any entity matches entity", schema.AnyEntityType{}, schema.EntityCedarType{Name: "User"}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := schema.TypesMatch(tc.expected, tc.actual)
			if got != tc.want {
				t.Errorf("TypesMatch(%v, %v) = %v, want %v", tc.expected, tc.actual, got, tc.want)
			}
		})
	}
}

func TestCedarTypeStrings(t *testing.T) {
	tests := []struct {
		typ  schema.CedarType
		want string
	}{
		{schema.BoolType{}, "Bool"},
		{schema.LongType{}, "Long"},
		{schema.StringType{}, "String"},
		{schema.EntityCedarType{Name: "User"}, "Entity<User>"},
		{schema.SetType{Element: schema.StringType{}}, "Set<String>"},
		{schema.ExtensionType{Name: "decimal"}, "decimal"},
		{schema.UnknownType{}, "Unknown"},
		{schema.AnyEntityType{}, "Entity"},
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
	rt := schema.RecordType{
		Attributes: map[string]schema.AttributeType{
			"name": {Type: schema.StringType{}, Required: true},
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
		expected schema.CedarType
		actual   schema.CedarType
		want     bool
	}{

		{"entity expected, any entity actual", schema.EntityCedarType{Name: "User"}, schema.AnyEntityType{}, true},
		{"entity expected, non-entity actual", schema.EntityCedarType{Name: "User"}, schema.StringType{}, false},

		{"any entity expected, entity actual", schema.AnyEntityType{}, schema.EntityCedarType{Name: "User"}, true},
		{"any entity expected, any entity actual", schema.AnyEntityType{}, schema.AnyEntityType{}, true},
		{"any entity expected, non-entity actual", schema.AnyEntityType{}, schema.StringType{}, false},
		{"any entity expected, long actual", schema.AnyEntityType{}, schema.LongType{}, false},

		{"set mismatch element", schema.SetType{Element: schema.StringType{}}, schema.SetType{Element: schema.LongType{}}, false},
		{"set expected, non-set actual", schema.SetType{Element: schema.StringType{}}, schema.LongType{}, false},

		{"record expected, non-record actual", schema.RecordType{}, schema.StringType{}, false},

		{"extension expected, non-extension actual", schema.ExtensionType{Name: "decimal"}, schema.StringType{}, false},

		{"default type", schema.RecordType{}, schema.RecordType{}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := schema.TypesMatch(tc.expected, tc.actual)
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
			ext, ok := inferred.(schema.ExtensionType)
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
	setType, ok := inferred.(schema.SetType)
	if !ok {
		t.Fatalf("Expected SetType, got %T", inferred)
	}
	_, isUnknown := setType.Element.(schema.UnknownType)
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
	// Test that type unification works correctly for if-then-else with compatible types.
	// Per Lean spec, `if true then 1 else 2 > 0` would parse as `if true then 1 else (2 > 0)`
	// which has incompatible branch types (Long and Bool) - this is a lubErr.
	// Here we use parentheses to ensure compatible types in branches.
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
	// Use parentheses to ensure both branches are Long
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { (if true then 1 else 2) > 0 };`)); err != nil {
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

	types := []schema.CedarType{
		schema.BoolType{},
		schema.LongType{},
		schema.StringType{},
		schema.EntityCedarType{Name: "User"},
		schema.SetType{Element: schema.StringType{}},
		schema.RecordType{},
		schema.ExtensionType{Name: "decimal"},
		schema.AnyEntityType{},
		schema.UnknownType{},
	}

	for _, ct := range types {
		// Verify it implements CedarType
		var _ schema.CedarType = ct
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
			expectValid: false, // emptySetErr: cannot infer element type of empty set literal (per Lean spec)
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

	recordType, ok := addressAttr.Type.(schema.RecordType)
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

// TestTypePredicateMethods tests all type predicate methods (IsBoolean, IsLong, etc.)
func TestTypePredicateMethods(t *testing.T) {
	tests := []struct {
		name      string
		typ       schema.CedarType
		isBoolean bool
		isLong    bool
		isString  bool
		isEntity  bool
		isSet     bool
		isRecord  bool
		isUnknown bool
	}{
		{"BoolType", schema.BoolType{}, true, false, false, false, false, false, false},
		{"LongType", schema.LongType{}, false, true, false, false, false, false, false},
		{"StringType", schema.StringType{}, false, false, true, false, false, false, false},
		{"EntityType", schema.EntityCedarType{Name: "User"}, false, false, false, true, false, false, false},
		{"SetType", schema.SetType{Element: schema.StringType{}}, false, false, false, false, true, false, false},
		{"RecordType", schema.RecordType{}, false, false, false, false, false, true, false},
		{"ExtensionType", schema.ExtensionType{Name: "decimal"}, false, false, false, false, false, false, false},
		{"AnyEntityType", schema.AnyEntityType{}, false, false, false, true, false, false, false},
		{"UnknownType", schema.UnknownType{}, false, false, false, false, false, false, true},
		{"UnspecifiedType", schema.UnspecifiedType{}, false, false, false, false, false, false, true}, // Treated as unknown
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checkTypePredicates(t, tc.name, tc.typ, tc.isBoolean, tc.isLong, tc.isString, tc.isEntity, tc.isSet, tc.isRecord, tc.isUnknown)
		})
	}
}

func checkTypePredicates(t *testing.T, name string, typ schema.CedarType, isBoolean, isLong, isString, isEntity, isSet, isRecord, isUnknown bool) {
	t.Helper()
	if got := typ.IsBoolean(); got != isBoolean {
		t.Errorf("%s.IsBoolean() = %v, want %v", name, got, isBoolean)
	}
	if got := typ.IsLong(); got != isLong {
		t.Errorf("%s.IsLong() = %v, want %v", name, got, isLong)
	}
	if got := typ.IsString(); got != isString {
		t.Errorf("%s.IsString() = %v, want %v", name, got, isString)
	}
	if got := typ.IsEntity(); got != isEntity {
		t.Errorf("%s.IsEntity() = %v, want %v", name, got, isEntity)
	}
	if got := typ.IsSet(); got != isSet {
		t.Errorf("%s.IsSet() = %v, want %v", name, got, isSet)
	}
	if got := typ.IsRecord(); got != isRecord {
		t.Errorf("%s.IsRecord() = %v, want %v", name, got, isRecord)
	}
	if got := typ.IsUnknown(); got != isUnknown {
		t.Errorf("%s.IsUnknown() = %v, want %v", name, got, isUnknown)
	}
}

// TestUnspecifiedTypeString tests the String() method for UnspecifiedType
func TestUnspecifiedTypeString(t *testing.T) {
	ut := schema.UnspecifiedType{}
	if got := ut.String(); got != "Unspecified" {
		t.Errorf("UnspecifiedType.String() = %q, want %q", got, "Unspecified")
	}

	// Verify it implements CedarType
	var _ schema.CedarType = ut
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
