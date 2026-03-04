package schema_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go/internal/testutil"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/schema/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema/resolved"
)

var wantCedar = `
@doc("Address information")
@personal_information
type Address = {
	@also("town")
	city: String,
	country: Country,
	street: String,
	zipcode?: String
};

type decimal = {
	decimal: Long,
	whole: Long
};

entity Admin;

entity Country;

entity System in Admin {
	version: String
};

entity Role enum ["superuser", "operator"];

action audit appliesTo {
	principal: Admin,
	resource: [MyApp::Document, System]
};

@doc("Doc manager")
namespace MyApp {
	type Metadata = {
		created: datetime,
		tags: Set<String>
	};

	entity Department {
		budget: decimal
	};

	entity Document {
		public: Bool,
		title: String
	};

	entity Group in Department {
		metadata: Metadata,
		name: String
	};

	@doc("User entity")
	entity User in Group {
		active: Bool,
		address: Address,
		email: String,
		level: Long
	};

	entity Status enum ["draft", "published", "archived"];

	@doc("View or edit document")
	action edit appliesTo {
		principal: User,
		resource: Document,
		context: {
			ip: ipaddr,
			timestamp: datetime
		}
	};

	action manage appliesTo {
		principal: User,
		resource: [Document, Group]
	};

	@doc("View or edit document")
	action view appliesTo {
		principal: User,
		resource: Document,
		context: {
			ip: ipaddr,
			timestamp: datetime
		}
	};
}
`

var wantJSON = `{
  "": {
    "entityTypes": {
      "Admin": {},
      "Country": {},
      "Role": {
        "enum": ["superuser", "operator"]
      },
      "System": {
        "memberOfTypes": ["Admin"],
        "shape": {
          "type": "Record",
          "attributes": {
            "version": {
              "type": "EntityOrCommon",
              "name": "String"
            }
          }
        }
      }
    },
    "actions": {
      "audit": {
        "appliesTo": {
          "principalTypes": ["Admin"],
          "resourceTypes": ["MyApp::Document", "System"]
        }
      }
    },
    "commonTypes": {
      "Address": {
        "type": "Record",
        "attributes": {
          "city": {
            "type": "EntityOrCommon",
            "name": "String",
            "annotations": {
              "also": "town"
            }
          },
          "country": {
            "type": "EntityOrCommon",
            "name": "Country"
          },
          "street": {
            "type": "EntityOrCommon",
            "name": "String"
          },
          "zipcode": {
            "type": "EntityOrCommon",
            "name": "String",
            "required": false
          }
        },
        "annotations": {
          "doc": "Address information",
          "personal_information": ""
        }
      },
      "decimal": {
        "type": "Record",
        "attributes": {
          "decimal": {
            "type": "EntityOrCommon",
            "name": "Long"
          },
          "whole": {
            "type": "EntityOrCommon",
            "name": "Long"
          }
        }
      }
    }
  },
  "MyApp": {
    "annotations": {
      "doc": "Doc manager"
    },
    "entityTypes": {
      "Department": {
        "shape": {
          "type": "Record",
          "attributes": {
            "budget": {
              "type": "EntityOrCommon",
              "name": "decimal"
            }
          }
        }
      },
      "Document": {
        "shape": {
          "type": "Record",
          "attributes": {
            "public": {
              "type": "EntityOrCommon",
              "name": "Bool"
            },
            "title": {
              "type": "EntityOrCommon",
              "name": "String"
            }
          }
        }
      },
      "Group": {
        "memberOfTypes": ["Department"],
        "shape": {
          "type": "Record",
          "attributes": {
            "metadata": {
              "type": "EntityOrCommon",
              "name": "Metadata"
            },
            "name": {
              "type": "EntityOrCommon",
              "name": "String"
            }
          }
        }
      },
      "Status": {
        "enum": ["draft", "published", "archived"]
      },
      "User": {
        "memberOfTypes": ["Group"],
        "shape": {
          "type": "Record",
          "attributes": {
            "active": {
              "type": "EntityOrCommon",
              "name": "Bool"
            },
            "address": {
              "type": "EntityOrCommon",
              "name": "Address"
            },
            "email": {
              "type": "EntityOrCommon",
              "name": "String"
            },
            "level": {
              "type": "EntityOrCommon",
              "name": "Long"
            }
          }
        },
        "annotations": {
          "doc": "User entity"
        }
      }
    },
    "actions": {
      "edit": {
        "appliesTo": {
          "principalTypes": ["User"],
          "resourceTypes": ["Document"],
          "context": {
            "type": "Record",
            "attributes": {
              "ip": {
                "type": "EntityOrCommon",
                "name": "ipaddr"
              },
              "timestamp": {
                "type": "EntityOrCommon",
                "name": "datetime"
              }
            }
          }
        },
        "annotations": {
          "doc": "View or edit document"
        }
      },
      "manage": {
        "appliesTo": {
          "principalTypes": ["User"],
          "resourceTypes": ["Document", "Group"]
        }
      },
      "view": {
        "appliesTo": {
          "principalTypes": ["User"],
          "resourceTypes": ["Document"],
          "context": {
            "type": "Record",
            "attributes": {
              "ip": {
                "type": "EntityOrCommon",
                "name": "ipaddr"
              },
              "timestamp": {
                "type": "EntityOrCommon",
                "name": "datetime"
              }
            }
          }
        },
        "annotations": {
          "doc": "View or edit document"
        }
      }
    },
    "commonTypes": {
      "Metadata": {
        "type": "Record",
        "attributes": {
          "created": {
            "type": "EntityOrCommon",
            "name": "datetime"
          },
          "tags": {
            "type": "Set",
            "element": {
              "type": "EntityOrCommon",
              "name": "String"
            }
          }
        }
      }
    }
  }
}`

// wantAST is the expected AST structure for the test schema.
var wantAST = &ast.Schema{
	CommonTypes: ast.CommonTypes{
		"Address": ast.CommonType{
			Annotations: ast.Annotations{
				"doc":                  "Address information",
				"personal_information": "",
			},
			Type: ast.RecordType{
				"city": ast.Attribute{
					Type: ast.TypeRef("String"),
					Annotations: ast.Annotations{
						"also": "town",
					},
				},
				"country": ast.Attribute{Type: ast.TypeRef("Country")},
				"street":  ast.Attribute{Type: ast.TypeRef("String")},
				"zipcode": ast.Attribute{Type: ast.TypeRef("String"), Optional: true},
			},
		},
		"decimal": ast.CommonType{
			Type: ast.RecordType{
				"decimal": ast.Attribute{Type: ast.TypeRef("Long")},
				"whole":   ast.Attribute{Type: ast.TypeRef("Long")},
			},
		},
	},
	Entities: ast.Entities{
		"Admin":   ast.Entity{},
		"Country": ast.Entity{},
		"System": ast.Entity{
			ParentTypes: []ast.EntityTypeRef{"Admin"},
			Shape: ast.RecordType{
				"version": ast.Attribute{Type: ast.TypeRef("String")},
			},
		},
	},
	Enums: ast.Enums{
		"Role": ast.Enum{
			Values: []types.String{"superuser", "operator"},
		},
	},
	Actions: ast.Actions{
		"audit": ast.Action{
			AppliesTo: &ast.AppliesTo{
				Principals: []ast.EntityTypeRef{"Admin"},
				Resources:  []ast.EntityTypeRef{"MyApp::Document", "System"},
			},
		},
	},
	Namespaces: ast.Namespaces{
		"MyApp": ast.Namespace{
			Annotations: ast.Annotations{
				"doc": "Doc manager",
			},
			CommonTypes: ast.CommonTypes{
				"Metadata": ast.CommonType{
					Type: ast.RecordType{
						"created": ast.Attribute{Type: ast.TypeRef("datetime")},
						"tags":    ast.Attribute{Type: ast.SetType{Element: ast.TypeRef("String")}},
					},
				},
			},
			Entities: ast.Entities{
				"Department": ast.Entity{
					Shape: ast.RecordType{
						"budget": ast.Attribute{Type: ast.TypeRef("decimal")},
					},
				},
				"Document": ast.Entity{
					Shape: ast.RecordType{
						"public": ast.Attribute{Type: ast.TypeRef("Bool")},
						"title":  ast.Attribute{Type: ast.TypeRef("String")},
					},
				},
				"Group": ast.Entity{
					ParentTypes: []ast.EntityTypeRef{"Department"},
					Shape: ast.RecordType{
						"metadata": ast.Attribute{Type: ast.TypeRef("Metadata")},
						"name":     ast.Attribute{Type: ast.TypeRef("String")},
					},
				},
				"User": ast.Entity{
					ParentTypes: []ast.EntityTypeRef{"Group"},
					Annotations: ast.Annotations{
						"doc": "User entity",
					},
					Shape: ast.RecordType{
						"active":  ast.Attribute{Type: ast.TypeRef("Bool")},
						"address": ast.Attribute{Type: ast.TypeRef("Address")},
						"email":   ast.Attribute{Type: ast.TypeRef("String")},
						"level":   ast.Attribute{Type: ast.TypeRef("Long")},
					},
				},
			},
			Enums: ast.Enums{
				"Status": ast.Enum{
					Values: []types.String{"draft", "published", "archived"},
				},
			},
			Actions: ast.Actions{
				"edit": ast.Action{
					Annotations: ast.Annotations{
						"doc": "View or edit document",
					},
					AppliesTo: &ast.AppliesTo{
						Principals: []ast.EntityTypeRef{"User"},
						Resources:  []ast.EntityTypeRef{"Document"},
						Context: ast.RecordType{
							"ip":        ast.Attribute{Type: ast.TypeRef("ipaddr")},
							"timestamp": ast.Attribute{Type: ast.TypeRef("datetime")},
						},
					},
				},
				"manage": ast.Action{
					AppliesTo: &ast.AppliesTo{
						Principals: []ast.EntityTypeRef{"User"},
						Resources:  []ast.EntityTypeRef{"Document", "Group"},
					},
				},
				"view": ast.Action{
					Annotations: ast.Annotations{
						"doc": "View or edit document",
					},
					AppliesTo: &ast.AppliesTo{
						Principals: []ast.EntityTypeRef{"User"},
						Resources:  []ast.EntityTypeRef{"Document"},
						Context: ast.RecordType{
							"ip":        ast.Attribute{Type: ast.TypeRef("ipaddr")},
							"timestamp": ast.Attribute{Type: ast.TypeRef("datetime")},
						},
					},
				},
			},
		},
	},
}

var wantResolved = &resolved.Schema{
	Namespaces: map[types.Path]resolved.Namespace{
		"MyApp": {
			Name: "MyApp",
			Annotations: resolved.Annotations{
				"doc": "Doc manager",
			},
		},
	},
	Entities: map[types.EntityType]resolved.Entity{
		"Admin":   {Name: "Admin"},
		"Country": {Name: "Country"},
		"System": {
			Name:        "System",
			ParentTypes: []types.EntityType{"Admin"},
			Shape: resolved.RecordType{
				"version": resolved.Attribute{Type: resolved.StringType{}},
			},
		},
		"MyApp::Department": {
			Name: "MyApp::Department",
			Shape: resolved.RecordType{
				"budget": resolved.Attribute{Type: resolved.RecordType{
					"decimal": resolved.Attribute{Type: resolved.LongType{}},
					"whole":   resolved.Attribute{Type: resolved.LongType{}},
				}},
			},
		},
		"MyApp::Document": {
			Name: "MyApp::Document",
			Shape: resolved.RecordType{
				"public": resolved.Attribute{Type: resolved.BoolType{}},
				"title":  resolved.Attribute{Type: resolved.StringType{}},
			},
		},
		"MyApp::Group": {
			Name:        "MyApp::Group",
			ParentTypes: []types.EntityType{"MyApp::Department"},
			Shape: resolved.RecordType{
				"metadata": resolved.Attribute{Type: resolved.RecordType{
					"created": resolved.Attribute{Type: resolved.ExtensionType("datetime")},
					"tags":    resolved.Attribute{Type: resolved.SetType{Element: resolved.StringType{}}},
				}},
				"name": resolved.Attribute{Type: resolved.StringType{}},
			},
		},
		"MyApp::User": {
			Name:        "MyApp::User",
			Annotations: resolved.Annotations{"doc": "User entity"},
			ParentTypes: []types.EntityType{"MyApp::Group"},
			Shape: resolved.RecordType{
				"active": resolved.Attribute{Type: resolved.BoolType{}},
				"address": resolved.Attribute{Type: resolved.RecordType{
					"city":    resolved.Attribute{Type: resolved.StringType{}, Annotations: resolved.Annotations{"also": "town"}},
					"country": resolved.Attribute{Type: resolved.EntityType("Country")},
					"street":  resolved.Attribute{Type: resolved.StringType{}},
					"zipcode": resolved.Attribute{Type: resolved.StringType{}, Optional: true},
				}},
				"email": resolved.Attribute{Type: resolved.StringType{}},
				"level": resolved.Attribute{Type: resolved.LongType{}},
			},
		},
	},
	Enums: map[types.EntityType]resolved.Enum{
		"Role":          {Name: "Role", Values: []types.EntityUID{types.NewEntityUID("Role", "superuser"), types.NewEntityUID("Role", "operator")}},
		"MyApp::Status": {Name: "MyApp::Status", Values: []types.EntityUID{types.NewEntityUID("MyApp::Status", "draft"), types.NewEntityUID("MyApp::Status", "published"), types.NewEntityUID("MyApp::Status", "archived")}},
	},
	Actions: map[types.EntityUID]resolved.Action{
		types.NewEntityUID("Action", "audit"): {
			Entity:    types.Entity{UID: types.NewEntityUID("Action", "audit"), Parents: types.NewEntityUIDSet()},
			AppliesTo: &resolved.AppliesTo{Principals: []types.EntityType{"Admin"}, Resources: []types.EntityType{"MyApp::Document", "System"}, Context: resolved.RecordType{}},
		},
		types.NewEntityUID("MyApp::Action", "edit"): {
			Entity:      types.Entity{UID: types.NewEntityUID("MyApp::Action", "edit"), Parents: types.NewEntityUIDSet()},
			Annotations: resolved.Annotations{"doc": "View or edit document"},
			AppliesTo: &resolved.AppliesTo{Principals: []types.EntityType{"MyApp::User"}, Resources: []types.EntityType{"MyApp::Document"}, Context: resolved.RecordType{
				"ip": resolved.Attribute{Type: resolved.ExtensionType("ipaddr")}, "timestamp": resolved.Attribute{Type: resolved.ExtensionType("datetime")},
			}},
		},
		types.NewEntityUID("MyApp::Action", "manage"): {
			Entity:    types.Entity{UID: types.NewEntityUID("MyApp::Action", "manage"), Parents: types.NewEntityUIDSet()},
			AppliesTo: &resolved.AppliesTo{Principals: []types.EntityType{"MyApp::User"}, Resources: []types.EntityType{"MyApp::Document", "MyApp::Group"}, Context: resolved.RecordType{}},
		},
		types.NewEntityUID("MyApp::Action", "view"): {
			Entity:      types.Entity{UID: types.NewEntityUID("MyApp::Action", "view"), Parents: types.NewEntityUIDSet()},
			Annotations: resolved.Annotations{"doc": "View or edit document"},
			AppliesTo: &resolved.AppliesTo{Principals: []types.EntityType{"MyApp::User"}, Resources: []types.EntityType{"MyApp::Document"}, Context: resolved.RecordType{
				"ip": resolved.Attribute{Type: resolved.ExtensionType("ipaddr")}, "timestamp": resolved.Attribute{Type: resolved.ExtensionType("datetime")},
			}},
		},
	},
}

func TestSchema(t *testing.T) {
	t.Parallel()

	t.Run("NewFromCedar", func(t *testing.T) {
		t.Parallel()
		s, err := schema.NewFromCedar("", []byte(wantCedar))
		testutil.OK(t, err)
		testutil.Equals(t, s.AST(), wantAST)
	})

	t.Run("NewFromJSON", func(t *testing.T) {
		t.Parallel()
		s, err := schema.NewFromJSON([]byte(wantJSON))
		testutil.OK(t, err)
		testutil.Equals(t, s.AST(), wantAST)
	})

	t.Run("MarshalCedar", func(t *testing.T) {
		t.Parallel()
		s, err := schema.NewSchemaFromAST(wantAST)
		testutil.OK(t, err)
		b, err := s.MarshalCedar()
		testutil.OK(t, err)
		stringEquals(t, string(b), wantCedar)
	})

	t.Run("MarshalJSON", func(t *testing.T) {
		t.Parallel()
		s, err := schema.NewSchemaFromAST(wantAST)
		testutil.OK(t, err)
		b, err := s.MarshalJSON()
		testutil.OK(t, err)
		stringEquals(t, string(normalizeJSON(t, b)), string(normalizeJSON(t, []byte(wantJSON))))
	})

	t.Run("Resolve", func(t *testing.T) {
		t.Parallel()
		s, err := schema.NewSchemaFromAST(wantAST)
		testutil.OK(t, err)
		r, err := s.Resolve()
		testutil.OK(t, err)
		testutil.Equals(t, r, wantResolved)
	})

	t.Run("CedarRoundTrip", func(t *testing.T) {
		t.Parallel()
		s, err := schema.NewFromCedar("", []byte(wantCedar))
		testutil.OK(t, err)
		b, err := s.MarshalCedar()
		testutil.OK(t, err)
		s2, err := schema.NewFromCedar("", b)
		testutil.OK(t, err)
		testutil.Equals(t, s2.AST(), wantAST)
	})

	t.Run("JSONRoundTrip", func(t *testing.T) {
		t.Parallel()
		s, err := schema.NewFromJSON([]byte(wantJSON))
		testutil.OK(t, err)
		b, err := s.MarshalJSON()
		testutil.OK(t, err)
		s2, err := schema.NewFromJSON(b)
		testutil.OK(t, err)
		testutil.Equals(t, s2.AST(), wantAST)
	})

	t.Run("CedarToJSONRoundTrip", func(t *testing.T) {
		t.Parallel()
		s, err := schema.NewFromCedar("", []byte(wantCedar))
		testutil.OK(t, err)
		jsonBytes, err := s.MarshalJSON()
		testutil.OK(t, err)
		s2, err := schema.NewFromJSON(jsonBytes)
		testutil.OK(t, err)
		testutil.Equals(t, s2.AST(), wantAST)
	})

	t.Run("JSONToCedarRoundTrip", func(t *testing.T) {
		t.Parallel()
		s, err := schema.NewFromJSON([]byte(wantJSON))
		testutil.OK(t, err)
		cedarBytes, err := s.MarshalCedar()
		testutil.OK(t, err)
		s2, err := schema.NewFromCedar("", cedarBytes)
		testutil.OK(t, err)
		testutil.Equals(t, s2.AST(), wantAST)
	})

	t.Run("JSONMarshalInterface", func(t *testing.T) {
		t.Parallel()
		s, err := schema.NewSchemaFromAST(wantAST)
		testutil.OK(t, err)
		b, err := json.Marshal(s)
		testutil.OK(t, err)
		s2, err := schema.NewFromJSON(b)
		testutil.OK(t, err)
		testutil.Equals(t, s2.AST(), wantAST)
	})

	t.Run("NewFromCedarErr", func(t *testing.T) {
		t.Parallel()
		_, err := schema.NewFromCedar("path/to/my-file-name.cedarschema", []byte("LSKJDFN"))
		testutil.Error(t, err)
		testutil.FatalIf(t, !strings.Contains(err.Error(), "path/to/my-file-name.cedarschema:1:1"), "expected filename in error: %v", err)
	})

	t.Run("NewFromJSONErr", func(t *testing.T) {
		t.Parallel()
		_, err := schema.NewFromJSON([]byte("LSKJDFN"))
		testutil.Error(t, err)
	})

	t.Run("ResolveErr", func(t *testing.T) {
		t.Parallel()
		// Schema with undefined entity type reference fails during construction
		_, err := schema.NewFromCedar("", []byte(`entity User in [NonExistent];`))
		testutil.Error(t, err)
	})

	t.Run("EmptySchema", func(t *testing.T) {
		t.Parallel()
		s, err := schema.NewSchemaFromAST(&ast.Schema{})
		testutil.OK(t, err)
		b, err := s.MarshalCedar()
		testutil.OK(t, err)
		testutil.Equals(t, string(b), "")
		jb, err := s.MarshalJSON()
		testutil.OK(t, err)
		testutil.Equals(t, string(jb), "{}")
	})

	t.Run("Introspection", func(t *testing.T) {
		t.Parallel()
		s, err := schema.NewFromCedar("", []byte(wantCedar))
		testutil.OK(t, err)
		etMap := s.EntityTypesMap()
		testutil.FatalIf(t, etMap == nil, "EntityTypesMap should not be nil")
		testutil.FatalIf(t, len(etMap) == 0, "EntityTypesMap should not be empty")
		atMap := s.ActionTypesMap()
		testutil.FatalIf(t, atMap == nil, "ActionTypesMap should not be nil")
		testutil.FatalIf(t, len(atMap) == 0, "ActionTypesMap should not be empty")
	})

	t.Run("FlatJSONSchema", func(t *testing.T) {
		t.Parallel()
		flatJSON := `{
			"entityTypes": {
				"User": {
					"memberOfTypes": ["Group"],
					"shape": { "type": "Record", "attributes": { "name": { "type": "EntityOrCommon", "name": "String" } } }
				},
				"Group": {}
			},
			"actions": {
				"view": { "appliesTo": { "principalTypes": ["User"], "resourceTypes": ["Group"] } }
			}
		}`
		s, err := schema.NewFromJSON([]byte(flatJSON))
		testutil.OK(t, err)
		testutil.FatalIf(t, s == nil, "schema should not be nil")
		_, hasUser := s.EntityTypesMap()["User"]
		testutil.FatalIf(t, !hasUser, "should have User entity type")
	})

	t.Run("SchemaFragment", func(t *testing.T) {
		t.Parallel()
		frag1, err := schema.NewFragmentFromCedar("", []byte(`
			entity User;
			action view appliesTo { principal: User, resource: User };
		`))
		testutil.OK(t, err)
		frag2, err := schema.NewFragmentFromCedar("", []byte(`entity Group;`))
		testutil.OK(t, err)
		s, err := schema.FromFragments(frag1, frag2)
		testutil.OK(t, err)
		testutil.FatalIf(t, s == nil, "schema from fragments should not be nil")
		etMap := s.EntityTypesMap()
		_, hasUser := etMap["User"]
		_, hasGroup := etMap["Group"]
		testutil.FatalIf(t, !hasUser, "should have User")
		testutil.FatalIf(t, !hasGroup, "should have Group")
	})

	t.Run("SchemaFragmentDuplicateError", func(t *testing.T) {
		t.Parallel()
		frag1, err := schema.NewFragmentFromCedar("", []byte(`entity User;`))
		testutil.OK(t, err)
		frag2, err := schema.NewFragmentFromCedar("", []byte(`entity User;`))
		testutil.OK(t, err)
		_, err = schema.FromFragments(frag1, frag2)
		testutil.Error(t, err)
	})
}

func stringEquals(t *testing.T, got, want string) {
	t.Helper()
	testutil.Equals(t, strings.TrimSpace(got), strings.TrimSpace(want))
}

func normalizeJSON(t *testing.T, in []byte) []byte {
	t.Helper()
	var out any
	err := json.Unmarshal(in, &out)
	testutil.OK(t, err)
	b, err := json.MarshalIndent(out, "", "  ")
	testutil.OK(t, err)
	return b
}
