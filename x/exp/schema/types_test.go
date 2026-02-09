package schema

import (
	"testing"

	"github.com/cedar-policy/cedar-go/types"
)

func TestCedarTypePredicates(t *testing.T) {
	tests := []struct {
		name      string
		typ       CedarType
		wantStr   string
		booleans  [7]bool // IsBoolean, IsLong, IsString, IsEntity, IsSet, IsRecord, IsUnknown
	}{
		{"BoolType", BoolType{}, "Bool", [7]bool{true, false, false, false, false, false, false}},
		{"LongType", LongType{}, "Long", [7]bool{false, true, false, false, false, false, false}},
		{"StringType", StringType{}, "String", [7]bool{false, false, true, false, false, false, false}},
		{"EntityCedarType", EntityCedarType{Name: "User"}, "Entity<User>", [7]bool{false, false, false, true, false, false, false}},
		{"SetType", SetType{Element: LongType{}}, "Set<Long>", [7]bool{false, false, false, false, true, false, false}},
		{"RecordType", RecordType{}, "Record", [7]bool{false, false, false, false, false, true, false}},
		{"ExtensionType", ExtensionType{Name: "decimal"}, "decimal", [7]bool{false, false, false, false, false, false, false}},
		{"AnyEntityType", AnyEntityType{}, "Entity", [7]bool{false, false, false, true, false, false, false}},
		{"UnknownType", UnknownType{}, "Unknown", [7]bool{false, false, false, false, false, false, true}},
		{"UnspecifiedType", UnspecifiedType{}, "Unspecified", [7]bool{false, false, false, false, false, false, true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify isCedarType compiles (interface satisfaction)
			var _ CedarType = tt.typ

			if got := tt.typ.String(); got != tt.wantStr {
				t.Errorf("String() = %q, want %q", got, tt.wantStr)
			}
			if got := tt.typ.IsBoolean(); got != tt.booleans[0] {
				t.Errorf("IsBoolean() = %v, want %v", got, tt.booleans[0])
			}
			if got := tt.typ.IsLong(); got != tt.booleans[1] {
				t.Errorf("IsLong() = %v, want %v", got, tt.booleans[1])
			}
			if got := tt.typ.IsString(); got != tt.booleans[2] {
				t.Errorf("IsString() = %v, want %v", got, tt.booleans[2])
			}
			if got := tt.typ.IsEntity(); got != tt.booleans[3] {
				t.Errorf("IsEntity() = %v, want %v", got, tt.booleans[3])
			}
			if got := tt.typ.IsSet(); got != tt.booleans[4] {
				t.Errorf("IsSet() = %v, want %v", got, tt.booleans[4])
			}
			if got := tt.typ.IsRecord(); got != tt.booleans[5] {
				t.Errorf("IsRecord() = %v, want %v", got, tt.booleans[5])
			}
			if got := tt.typ.IsUnknown(); got != tt.booleans[6] {
				t.Errorf("IsUnknown() = %v, want %v", got, tt.booleans[6])
			}
		})
	}
}

func TestTypesMatch(t *testing.T) {
	tests := []struct {
		name     string
		expected CedarType
		actual   CedarType
		want     bool
	}{
		// Primitive matches
		{"Bool-Bool", BoolType{}, BoolType{}, true},
		{"Bool-Long", BoolType{}, LongType{}, false},
		{"Long-Long", LongType{}, LongType{}, true},
		{"Long-String", LongType{}, StringType{}, false},
		{"String-String", StringType{}, StringType{}, true},
		{"String-Bool", StringType{}, BoolType{}, false},

		// Entity matches
		{"Entity-same", EntityCedarType{Name: "User"}, EntityCedarType{Name: "User"}, true},
		{"Entity-diff", EntityCedarType{Name: "User"}, EntityCedarType{Name: "Doc"}, false},
		{"Entity-AnyEntity", EntityCedarType{Name: "User"}, AnyEntityType{}, true},
		{"Entity-String", EntityCedarType{Name: "User"}, StringType{}, false},

		// AnyEntity matches
		{"AnyEntity-Entity", AnyEntityType{}, EntityCedarType{Name: "User"}, true},
		{"AnyEntity-AnyEntity", AnyEntityType{}, AnyEntityType{}, true},
		{"AnyEntity-String", AnyEntityType{}, StringType{}, false},

		// Set matches
		{"Set-Set-same", SetType{Element: LongType{}}, SetType{Element: LongType{}}, true},
		{"Set-Set-diff", SetType{Element: LongType{}}, SetType{Element: StringType{}}, false},
		{"Set-String", SetType{Element: LongType{}}, StringType{}, false},

		// Record matches
		{"Record-empty", RecordType{Attributes: map[string]AttributeType{}}, RecordType{Attributes: map[string]AttributeType{}}, true},
		{"Record-match", RecordType{Attributes: map[string]AttributeType{
			"name": {Type: StringType{}, Required: true},
		}}, RecordType{Attributes: map[string]AttributeType{
			"name": {Type: StringType{}, Required: true},
		}}, true},
		{"Record-missing-required", RecordType{Attributes: map[string]AttributeType{
			"name": {Type: StringType{}, Required: true},
		}}, RecordType{Attributes: map[string]AttributeType{}}, false},
		{"Record-missing-optional", RecordType{Attributes: map[string]AttributeType{
			"name": {Type: StringType{}, Required: false},
		}}, RecordType{Attributes: map[string]AttributeType{}}, true},
		{"Record-type-mismatch", RecordType{Attributes: map[string]AttributeType{
			"name": {Type: StringType{}, Required: true},
		}}, RecordType{Attributes: map[string]AttributeType{
			"name": {Type: LongType{}, Required: true},
		}}, false},
		{"Record-not-record", RecordType{}, StringType{}, false},

		// Extension matches
		{"Extension-same", ExtensionType{Name: "decimal"}, ExtensionType{Name: "decimal"}, true},
		{"Extension-diff", ExtensionType{Name: "decimal"}, ExtensionType{Name: "ipaddr"}, false},
		{"Extension-String", ExtensionType{Name: "decimal"}, StringType{}, false},

		// Unknown matches everything
		{"Unknown-Bool", UnknownType{}, BoolType{}, true},
		{"Unknown-String", UnknownType{}, StringType{}, true},
		{"Unknown-Entity", UnknownType{}, EntityCedarType{Name: "User"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TypesMatch(tt.expected, tt.actual); got != tt.want {
				t.Errorf("TypesMatch(%s, %s) = %v, want %v", tt.expected, tt.actual, got, tt.want)
			}
		})
	}
}

func TestTypesMatchDefaultCase(t *testing.T) {
	// UnspecifiedType falls into the default case (returns false)
	if TypesMatch(UnspecifiedType{}, BoolType{}) {
		t.Error("TypesMatch(UnspecifiedType, BoolType) should be false")
	}
}

func TestEntityTypeInfo(t *testing.T) {
	info := EntityTypeInfo{
		Attributes:    map[string]AttributeType{"name": {Type: StringType{}, Required: true}},
		MemberOfTypes: []types.EntityType{"Group"},
		OpenRecord:    false,
	}
	if _, ok := info.Attributes["name"]; !ok {
		t.Error("expected name attribute")
	}
	if len(info.MemberOfTypes) != 1 {
		t.Errorf("expected 1 memberOfType, got %d", len(info.MemberOfTypes))
	}
}

func TestActionTypeInfo(t *testing.T) {
	info := ActionTypeInfo{
		PrincipalTypes: []types.EntityType{"User"},
		ResourceTypes:  []types.EntityType{"Document"},
		Context:        RecordType{Attributes: map[string]AttributeType{}},
		MemberOf:       []types.EntityUID{{Type: "Action", ID: "parent"}},
	}
	if len(info.PrincipalTypes) != 1 || len(info.ResourceTypes) != 1 {
		t.Error("unexpected type counts")
	}
	if len(info.MemberOf) != 1 {
		t.Errorf("expected 1 memberOf, got %d", len(info.MemberOf))
	}
}

func TestRequestEnvStruct(t *testing.T) {
	env := RequestEnv{
		PrincipalType: "User",
		Action:        types.NewEntityUID("Action", "view"),
		ResourceType:  "Document",
	}
	if env.PrincipalType != "User" {
		t.Errorf("unexpected PrincipalType: %s", env.PrincipalType)
	}
}

// TestIsCedarType explicitly calls the private isCedarType() methods
// to ensure coverage of interface marker methods.
func TestIsCedarType(t *testing.T) {
	// Each call exercises the isCedarType marker method
	BoolType{}.isCedarType()
	LongType{}.isCedarType()
	StringType{}.isCedarType()
	EntityCedarType{}.isCedarType()
	SetType{}.isCedarType()
	RecordType{}.isCedarType()
	ExtensionType{}.isCedarType()
	AnyEntityType{}.isCedarType()
	UnknownType{}.isCedarType()
	UnspecifiedType{}.isCedarType()
}
