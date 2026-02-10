package schema

import (
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go/internal/schema/ast"
	"github.com/cedar-policy/cedar-go/types"
)

// --- Schema parsing: All Cedar types ---

// Verify that every Cedar type (Bool, Long, String, Entity, Set, Record, Extension)
// is correctly parsed and available via EntityTypeInfoFor.
func TestParseAllCedarTypes(t *testing.T) {
	src := `{
		"entityTypes": {
			"Session": {},
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {
						"active":  {"type": "Boolean"},
						"active2": {"type": "Bool"},
						"age":     {"type": "Long"},
						"name":    {"type": "String"},
						"manager": {"type": "Entity", "name": "User"},
						"anyRef":  {"type": "Entity"},
						"tags":    {"type": "Set", "element": {"type": "String"}},
						"emptySet":{"type": "Set"},
						"metadata":{"type": "Record", "attributes": {"key": {"type": "String"}}},
						"score":   {"type": "Extension", "name": "decimal"},
						"ip":      {"type": "Extension", "name": "ipaddr"},
						"noext":   {"type": "Extension"}
					}
				}
			}
		}
	}`
	s, err := NewFromJSON([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	info, ok := s.EntityTypeInfoFor("User")
	if !ok {
		t.Fatal("User not found")
	}

	checks := []struct {
		attr     string
		wantType string
	}{
		{"active", "Bool"},
		{"active2", "Bool"},
		{"age", "Long"},
		{"name", "String"},
		{"manager", "Entity<User>"},
		{"anyRef", "Entity"},
		{"tags", "Set<String>"},
		{"emptySet", "Set<Unknown>"},
		{"metadata", "Record"},
		{"score", "decimal"},
		{"ip", "ipaddr"},
		{"noext", "Unknown"},
	}

	for _, c := range checks {
		attr, ok := info.Attributes[c.attr]
		if !ok {
			t.Errorf("attribute %q not found", c.attr)
			continue
		}
		if got := attr.Type.String(); got != c.wantType {
			t.Errorf("attribute %q: type = %q, want %q", c.attr, got, c.wantType)
		}
	}
}

// --- Schema parsing: Edge cases ---

// Entity with no shape gets OpenRecord=true, allowing any attributes.
func TestEntityWithoutShapeIsOpenRecord(t *testing.T) {
	s, err := NewFromJSON([]byte(`{"entityTypes": {"User": {}}}`))
	if err != nil {
		t.Fatal(err)
	}
	info, ok := s.EntityTypeInfoFor("User")
	if !ok {
		t.Fatal("User not found")
	}
	if !info.OpenRecord {
		t.Error("entity without shape should be open record")
	}
}

// An unrecognized type name that looks like an entity reference should be
// parsed as EntityCedarType, while invalid identifiers become UnspecifiedType.
func TestTypeReferenceResolution(t *testing.T) {
	src := `{
		"entityTypes": {
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {
						"validRef":   {"type": "SomeType"},
						"invalidRef": {"type": "123-bad"},
						"emptyRef":   {"type": ""}
					}
				}
			}
		}
	}`
	s, err := NewFromJSON([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	info, _ := s.EntityTypeInfoFor("User")

	// Valid identifier but unknown type → EntityCedarType (assumed entity reference)
	if attr, ok := info.Attributes["validRef"]; ok {
		if _, isEntity := attr.Type.(EntityCedarType); !isEntity {
			t.Errorf("validRef: got %T, want EntityCedarType", attr.Type)
		}
	}

	// Invalid identifier → UnspecifiedType
	if attr, ok := info.Attributes["invalidRef"]; ok {
		if _, isUnspec := attr.Type.(UnspecifiedType); !isUnspec {
			t.Errorf("invalidRef: got %T, want UnspecifiedType", attr.Type)
		}
	}

	// Empty string → UnspecifiedType
	if attr, ok := info.Attributes["emptyRef"]; ok {
		if _, isUnspec := attr.Type.(UnspecifiedType); !isUnspec {
			t.Errorf("emptyRef: got %T, want UnspecifiedType", attr.Type)
		}
	}
}

// Action with explicit memberOf type should preserve the custom type name.
func TestActionMemberOfExplicitType(t *testing.T) {
	src := `{
		"entityTypes": {"User": {}, "Document": {}},
		"actions": {
			"manage_docs": {"memberOf": []},
			"delete": {
				"memberOf": [{"type": "Custom::Action", "id": "manage_docs"}],
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["Document"]
				}
			}
		}
	}`
	s, err := NewFromJSON([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	deleteAction := types.NewEntityUID("Action", "delete")
	info, ok := s.ActionInfo(deleteAction)
	if !ok {
		t.Fatal("delete action not found")
	}
	if len(info.MemberOf) != 1 {
		t.Fatalf("expected 1 memberOf, got %d", len(info.MemberOf))
	}
	if info.MemberOf[0].Type != "Custom::Action" {
		t.Errorf("memberOf type = %q, want Custom::Action", info.MemberOf[0].Type)
	}
}

// --- Schema validation: Identifier validation ---

// Ensure that invalid identifiers in principalTypes/resourceTypes are caught
// during schema construction, not silently accepted.
func TestInvalidPrincipalResourceTypeIdentifiers(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"digit-start principalType", `{"entityTypes":{"User":{}},"actions":{"v":{"appliesTo":{"principalTypes":["9Bad"],"resourceTypes":["User"]}}}}`},
		{"digit-start resourceType", `{"entityTypes":{"User":{}},"actions":{"v":{"appliesTo":{"principalTypes":["User"],"resourceTypes":["9Bad"]}}}}`},
		{"hyphen in principalType", `{"entityTypes":{"User":{}},"actions":{"v":{"appliesTo":{"principalTypes":["bad-type"],"resourceTypes":["User"]}}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewFromJSON([]byte(tt.input))
			if err == nil {
				t.Error("expected validation error for invalid identifier")
			}
		})
	}
}

// --- Internal helpers ---

func TestIsPrimitiveType(t *testing.T) {
	for _, name := range []string{"String", "Long", "Bool", "Boolean", "Record", "Set", "Extension", "Entity", "EntityOrCommon"} {
		if !isPrimitiveType(name) {
			t.Errorf("isPrimitiveType(%q) should be true", name)
		}
	}
	for _, name := range []string{"", "User", "Custom", "integer"} {
		if isPrimitiveType(name) {
			t.Errorf("isPrimitiveType(%q) should be false", name)
		}
	}
}

func TestIsValidTypeIdentifier(t *testing.T) {
	valid := []string{"User", "NS::Type", "_Foo", "Foo123"}
	for _, v := range valid {
		if !isValidTypeIdentifier(v) {
			t.Errorf("isValidTypeIdentifier(%q) should be true", v)
		}
	}
	invalid := []string{"", "123", "NS::123", "a-b"}
	for _, v := range invalid {
		if isValidTypeIdentifier(v) {
			t.Errorf("isValidTypeIdentifier(%q) should be false", v)
		}
	}
}

func TestIsValidParseCedarIdent(t *testing.T) {
	valid := []string{"a", "_a", "A", "abc1", "foo_bar"}
	for _, v := range valid {
		if !isValidParseCedarIdent(v) {
			t.Errorf("isValidParseCedarIdent(%q) should be true", v)
		}
	}
	invalid := []string{"", "1abc", "a-b", "a b"}
	for _, v := range invalid {
		if isValidParseCedarIdent(v) {
			t.Errorf("isValidParseCedarIdent(%q) should be false", v)
		}
	}
}

func TestIsValidParseTypeReference(t *testing.T) {
	valid := []string{"User", "NS::User", "A::B::C"}
	for _, v := range valid {
		if !isValidParseTypeReference(v) {
			t.Errorf("isValidParseTypeReference(%q) should be true", v)
		}
	}
	invalid := []string{"", "NS::123", "::User"}
	for _, v := range invalid {
		if isValidParseTypeReference(v) {
			t.Errorf("isValidParseTypeReference(%q) should be false", v)
		}
	}
}

// --- NewFromCedar / NewFragmentFromCedar error paths ---

func TestNewFromCedarInvalidSyntax(t *testing.T) {
	_, err := NewFromCedar("test.cedarschema", []byte("this is not valid cedar schema {{{"))
	if err == nil {
		t.Error("expected parse error for invalid Cedar syntax")
	}
}

func TestNewFragmentFromCedarInvalidSyntax(t *testing.T) {
	_, err := NewFragmentFromCedar("test.cedarschema", []byte("this is not valid cedar schema {{{"))
	if err == nil {
		t.Error("expected parse error for invalid Cedar syntax")
	}
}

// --- Schema merge edge cases ---

// Merging with a null namespace in the source should skip it silently.
func TestMergeWithNilSourceNamespace(t *testing.T) {
	frag1, _ := NewFragmentFromJSON([]byte(`{"app": {"entityTypes": {"User": {}}}}`))
	frag2, _ := NewFragmentFromJSON([]byte(`{"app": null}`))

	result, err := frag1.Merge(frag2)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("merge result should not be nil")
	}
}

// Duplicate common types across fragments must produce an error.
func TestMergeDuplicateCommonType(t *testing.T) {
	frag1, _ := NewFragmentFromJSON([]byte(`{"app": {"commonTypes": {"Email": {"type": "String"}}}}`))
	frag2, _ := NewFragmentFromJSON([]byte(`{"app": {"commonTypes": {"Email": {"type": "Long"}}}}`))

	_, err := frag1.Merge(frag2)
	if err == nil {
		t.Error("expected error for duplicate common type")
	}
	if !strings.Contains(err.Error(), "duplicate common type") {
		t.Errorf("error should mention duplicate common type, got: %v", err)
	}
}

// Duplicate actions across fragments must produce an error.
func TestMergeDuplicateAction(t *testing.T) {
	frag1, _ := NewFragmentFromJSON([]byte(`{"app": {"actions": {"view": {"appliesTo": {"principalTypes": [], "resourceTypes": []}}}}}`))
	frag2, _ := NewFragmentFromJSON([]byte(`{"app": {"actions": {"view": {"appliesTo": {"principalTypes": [], "resourceTypes": []}}}}}`))

	_, err := frag1.Merge(frag2)
	if err == nil {
		t.Error("expected error for duplicate action")
	}
	if !strings.Contains(err.Error(), "duplicate action") {
		t.Errorf("error should mention duplicate action, got: %v", err)
	}
}

// Merging two empty fragments (nil jsonSchema) should not panic.
func TestMergeEmptyFragments(t *testing.T) {
	f := &SchemaFragment{}
	other := &SchemaFragment{}
	result, err := f.Merge(other)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
}

// A successful merge of two namespaces with non-overlapping entities,
// actions, and common types exercises all loop paths in mergeNamespaces.
func TestMergeSuccessfulWithAllTypes(t *testing.T) {
	frag1, _ := NewFragmentFromJSON([]byte(`{
		"app": {
			"entityTypes": {"User": {}},
			"actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["User"]}}},
			"commonTypes": {"Name": {"type": "String"}}
		}
	}`))
	frag2, _ := NewFragmentFromJSON([]byte(`{
		"app": {
			"entityTypes": {"Doc": {}},
			"actions": {"edit": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Doc"]}}},
			"commonTypes": {"Age": {"type": "Long"}}
		}
	}`))

	result, err := frag1.Merge(frag2)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
}

// --- Validation: undefined type references ---

// FromFragments must detect undefined principal type references.
func TestFromFragmentsUndefinedPrincipalTypeRef(t *testing.T) {
	frag, _ := NewFragmentFromJSON([]byte(`{
		"app": {
			"entityTypes": {"Document": {}},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["MissingUser"],
						"resourceTypes": ["Document"]
					}
				}
			}
		}
	}`))
	_, err := FromFragments(frag)
	if err == nil {
		t.Error("expected error for undefined principal type reference")
	}
	if !strings.Contains(err.Error(), "principal type") {
		t.Errorf("error should mention principal type, got: %v", err)
	}
}

// FromFragments must detect undefined resource type references.
func TestFromFragmentsUndefinedResourceTypeRef(t *testing.T) {
	frag, _ := NewFragmentFromJSON([]byte(`{
		"app": {
			"entityTypes": {"User": {}},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["MissingDoc"]
					}
				}
			}
		}
	}`))
	_, err := FromFragments(frag)
	if err == nil {
		t.Error("expected error for undefined resource type reference")
	}
	if !strings.Contains(err.Error(), "resource type") {
		t.Errorf("error should mention resource type, got: %v", err)
	}
}

// FromFragments must detect undefined memberOf type references.
func TestFromFragmentsUndefinedMemberOfRef(t *testing.T) {
	frag, _ := NewFragmentFromJSON([]byte(`{
		"app": {
			"entityTypes": {
				"User": {"memberOfTypes": ["MissingGroup"]}
			}
		}
	}`))
	_, err := FromFragments(frag)
	if err == nil {
		t.Error("expected error for undefined memberOf type reference")
	}
}

// FromFragments with an action context referencing an undefined entity type.
func TestFromFragmentsUndefinedContextRef(t *testing.T) {
	frag, _ := NewFragmentFromJSON([]byte(`{
		"app": {
			"entityTypes": {"User": {}, "Document": {}},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"],
						"context": {
							"type": "Record",
							"attributes": {
								"session": {"type": "Entity", "name": "UndefinedSession"}
							}
						}
					}
				}
			}
		}
	}`))
	_, err := FromFragments(frag)
	if err == nil {
		t.Error("expected error for undefined context entity reference")
	}
}

// FromFragments with a common type referencing an undefined entity.
func TestFromFragmentsUndefinedCommonTypeRef(t *testing.T) {
	frag, _ := NewFragmentFromJSON([]byte(`{
		"app": {
			"commonTypes": {
				"SessionRef": {"type": "Entity", "name": "UndefinedSession"}
			},
			"entityTypes": {"User": {}}
		}
	}`))
	_, err := FromFragments(frag)
	if err == nil {
		t.Error("expected error for undefined common type entity reference")
	}
}

// FromFragments with a set element referencing an undefined entity.
func TestFromFragmentsUndefinedSetElementRef(t *testing.T) {
	frag, _ := NewFragmentFromJSON([]byte(`{
		"app": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"refs": {"type": "Set", "element": {"type": "Entity", "name": "UndefinedType"}}
						}
					}
				}
			}
		}
	}`))
	_, err := FromFragments(frag)
	if err == nil {
		t.Error("expected error for undefined set element entity reference")
	}
}

// FromFragments with a nested record referencing an undefined entity.
func TestFromFragmentsUndefinedRecordAttrRef(t *testing.T) {
	frag, _ := NewFragmentFromJSON([]byte(`{
		"app": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"nested": {
								"type": "Record",
								"attributes": {
									"ref": {"type": "Entity", "name": "Undefined"}
								}
							}
						}
					}
				}
			}
		}
	}`))
	_, err := FromFragments(frag)
	if err == nil {
		t.Error("expected error for undefined nested record reference")
	}
}

// FromFragments with an undefined tag entity reference.
func TestFromFragmentsUndefinedTagRef(t *testing.T) {
	frag, _ := NewFragmentFromJSON([]byte(`{
		"app": {
			"entityTypes": {
				"User": {
					"tags": {"type": "Entity", "name": "UndefinedTag"}
				}
			}
		}
	}`))
	_, err := FromFragments(frag)
	if err == nil {
		t.Error("expected error for undefined tag entity reference")
	}
}

// --- Flat schema error paths ---

func TestNewFromJSONFlatSchemaUnmarshalError(t *testing.T) {
	_, err := NewFromJSON([]byte(`{"entityTypes": "not_an_object"}`))
	if err == nil {
		t.Error("expected unmarshal error for invalid entityTypes value")
	}
}

func TestNewFragmentFromJSONFlatSchemaUnmarshalError(t *testing.T) {
	_, err := NewFragmentFromJSON([]byte(`{"entityTypes": "not_an_object"}`))
	if err == nil {
		t.Error("expected unmarshal error for invalid entityTypes value")
	}
}

func TestNewFromJSONFlatSchemaInvalidIdentifier(t *testing.T) {
	_, err := NewFromJSON([]byte(`{"entityTypes": {"123Invalid": {}}}`))
	if err == nil {
		t.Error("expected validation error for invalid entity type identifier in flat schema")
	}
}

func TestNewFragmentFromJSONFlatSchemaInvalidIdentifier(t *testing.T) {
	_, err := NewFragmentFromJSON([]byte(`{"entityTypes": {"123Invalid": {}}}`))
	if err == nil {
		t.Error("expected validation error for invalid entity type identifier in flat schema")
	}
}

func TestNewFromJSONNamespaceFormatInvalid(t *testing.T) {
	_, err := NewFromJSON([]byte(`{"app": "not_an_object"}`))
	if err == nil {
		t.Error("expected error for non-object namespace value")
	}
}

// --- Validation: type reference resolution paths ---

// Fully qualified references (e.g., "app::User") must resolve correctly.
func TestFromFragmentsFullyQualifiedReference(t *testing.T) {
	frag, _ := NewFragmentFromJSON([]byte(`{
		"app": {
			"entityTypes": {
				"User": {},
				"Admin": {"memberOfTypes": ["app::User"]}
			}
		}
	}`))
	_, err := FromFragments(frag)
	if err != nil {
		t.Errorf("fully qualified reference should resolve: %v", err)
	}
}

// Set type without an explicit element should pass validation.
func TestFromFragmentsSetWithoutElement(t *testing.T) {
	frag, _ := NewFragmentFromJSON([]byte(`{
		"app": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"tags": {"type": "Set"}
						}
					}
				}
			}
		}
	}`))
	_, err := FromFragments(frag)
	if err != nil {
		t.Errorf("set without element should be valid: %v", err)
	}
}

// Extension type exercises the default case in validateDefaultTypeRef.
func TestFromFragmentsExtensionType(t *testing.T) {
	frag, _ := NewFragmentFromJSON([]byte(`{
		"app": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"score": {"type": "Extension", "name": "decimal"}
						}
					}
				}
			}
		}
	}`))
	_, err := FromFragments(frag)
	if err != nil {
		t.Errorf("extension type should be valid: %v", err)
	}
}

// Entity with valid tags should pass validation.
func TestFromFragmentsEntityWithTags(t *testing.T) {
	frag, _ := NewFragmentFromJSON([]byte(`{
		"app": {
			"entityTypes": {
				"User": {
					"tags": {"type": "Set", "element": {"type": "String"}}
				}
			}
		}
	}`))
	_, err := FromFragments(frag)
	if err != nil {
		t.Errorf("entity with tags should be valid: %v", err)
	}
}

// --- Null/nil edge cases ---

func TestNullNamespaceSkipped(t *testing.T) {
	s, err := NewFromJSON([]byte(`{"app": null}`))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for range s.EntityTypes() {
		count++
	}
	if count != 0 {
		t.Errorf("null namespace should produce 0 entity types, got %d", count)
	}
}

func TestFromFragmentsNullNamespaceEntry(t *testing.T) {
	frag, _ := NewFragmentFromJSON([]byte(`{
		"": {"entityTypes": {"User": {}}},
		"other": null
	}`))
	_, err := FromFragments(frag)
	if err != nil {
		t.Errorf("null namespace should be skipped: %v", err)
	}
}

func TestFromFragmentsNullCommonTypeEntry(t *testing.T) {
	frag, _ := NewFragmentFromJSON([]byte(`{
		"app": {
			"commonTypes": {"NullType": null},
			"entityTypes": {"User": {}}
		}
	}`))
	_, err := FromFragments(frag)
	if err != nil {
		t.Errorf("null common type should be skipped: %v", err)
	}
}

func TestFromFragmentsAllNil(t *testing.T) {
	schema, err := FromFragments(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if schema == nil {
		t.Fatal("FromFragments(nil, nil) should return non-nil schema")
	}
}

func TestFromFragmentsSingleNil(t *testing.T) {
	s, err := FromFragments(nil)
	if err != nil {
		t.Fatal(err)
	}
	if s == nil {
		t.Fatal("FromFragments(nil) should return non-nil schema")
	}
}

// --- Coverage: parse.go parseJSONType switch cases ---

// "Bool" (not "Boolean") in a common type exercises the "Bool" case in parseJSONType.
func TestParseJSONTypeBoolVariant(t *testing.T) {
	src := `{
		"entityTypes": {"User": {}},
		"commonTypes": {"Flag": {"type": "Bool"}}
	}`
	s, err := NewFromJSON([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	// Verify the common type parsed as BoolType
	ct, ok := s.CommonTypesMap()["Flag"]
	if !ok {
		t.Fatal("Flag common type not found")
	}
	if _, isBool := ct.(BoolType); !isBool {
		t.Errorf("Flag: got %T, want BoolType", ct)
	}
}

// "Extension" type in a common type exercises the "Extension" case in parseJSONType.
func TestParseJSONTypeExtensionVariant(t *testing.T) {
	src := `{
		"entityTypes": {"User": {}},
		"commonTypes": {"Score": {"type": "Extension", "name": "decimal"}}
	}`
	s, err := NewFromJSON([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	ct, ok := s.CommonTypesMap()["Score"]
	if !ok {
		t.Fatal("Score common type not found")
	}
	if ext, isExt := ct.(ExtensionType); !isExt {
		t.Errorf("Score: got %T, want ExtensionType", ct)
	} else if ext.Name != "decimal" {
		t.Errorf("Score extension name = %q, want %q", ext.Name, "decimal")
	}
}

// --- Coverage: schema.go validation paths ---

// NewFragmentFromJSON with namespace-format JSON containing invalid identifiers
// exercises the validateIdentifiers error path in the namespace branch (line 227).
func TestNewFragmentFromJSONNamespaceInvalidIdentifier(t *testing.T) {
	_, err := NewFragmentFromJSON([]byte(`{"app": {"entityTypes": {"123Bad": {}}}}`))
	if err == nil {
		t.Error("expected validation error for invalid entity type identifier in namespace format")
	}
}

// FromFragments with a Record attribute set to null exercises the nil-attr
// guard in both validateRecordTypeRef and validateRecordTypeReferences.
func TestFromFragmentsNullRecordAttribute(t *testing.T) {
	frag, err := NewFragmentFromJSON([]byte(`{
		"app": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"name": {"type": "String"},
							"extra": null
						}
					}
				}
			}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = FromFragments(frag)
	if err != nil {
		t.Errorf("null record attribute should be skipped gracefully: %v", err)
	}
}

// FromFragments with a non-primitive type referencing an undefined name exercises
// the validateDefaultTypeRef error path (line 593).
func TestFromFragmentsDefaultTypeRefUndefined(t *testing.T) {
	frag, err := NewFragmentFromJSON([]byte(`{
		"app": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"ref": {"type": "CustomType", "name": "UndefinedRef"}
						}
					}
				}
			}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = FromFragments(frag)
	if err == nil {
		t.Error("expected error for undefined type reference in default type ref path")
	}
}

// FromFragments with a primitive type name as principalType exercises the
// isPrimitiveType check in isDefinedType (line 602).
func TestFromFragmentsPrimitiveAsPrincipalType(t *testing.T) {
	frag, err := NewFragmentFromJSON([]byte(`{
		"": {
			"entityTypes": {"String": {}},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["String"],
						"resourceTypes": ["String"]
					}
				}
			}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = FromFragments(frag)
	if err != nil {
		t.Errorf("primitive type name as principalType should be valid: %v", err)
	}
}

// EntityOrCommon type with an invalid identifier in the name exercises
// validateEntityOrCommonReference (line 859).
// EntityOrCommon type with an empty name exercises the early-return path
// in validateEntityOrCommonReference (line 859).
func TestValidateEntityOrCommonEmptyName(t *testing.T) {
	_, err := NewFromJSON([]byte(`{
		"app": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"ref": {"type": "EntityOrCommon"}
						}
					}
				}
			}
		}
	}`))
	if err != nil {
		t.Errorf("EntityOrCommon with empty name should be valid: %v", err)
	}
}

func TestValidateEntityOrCommonInvalidIdentifier(t *testing.T) {
	_, err := NewFromJSON([]byte(`{
		"app": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"ref": {"type": "EntityOrCommon", "name": "bad!name"}
						}
					}
				}
			}
		}
	}`))
	if err == nil {
		t.Error("expected error for EntityOrCommon with invalid identifier")
	}
	if err != nil && !strings.Contains(err.Error(), "invalid identifier") {
		t.Errorf("error should mention invalid identifier, got: %v", err)
	}
}

// FromFragments with a directly constructed fragment containing invalid identifiers
// exercises the validateIdentifiers error path in FromFragments (line 333).
func TestFromFragmentsValidateIdentifiersError(t *testing.T) {
	badFrag := &SchemaFragment{
		jsonSchema: ast.JSONSchema{
			"app": &ast.JSONNamespace{
				EntityTypes: map[string]*ast.JSONEntity{
					"123Bad": {},
				},
				Actions:     make(map[string]*ast.JSONAction),
				CommonTypes: make(map[string]*ast.JSONCommonType),
			},
		},
	}
	_, err := FromFragments(badFrag)
	if err == nil {
		t.Error("expected validation error for invalid identifier in FromFragments")
	}
}
