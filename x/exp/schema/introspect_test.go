package schema

import (
	"slices"
	"testing"

	"github.com/cedar-policy/cedar-go/types"
)

func newTestSchema(t *testing.T) *Schema {
	t.Helper()
	src := `{
		"MyApp": {
			"entityTypes": {
				"User": {
					"memberOfTypes": ["Group"],
					"shape": {
						"type": "Record",
						"attributes": {
							"name": {"type": "String", "required": true}
						}
					}
				},
				"Group": {},
				"Document": {
					"shape": {
						"type": "Record",
						"attributes": {
							"owner": {"type": "Entity", "name": "MyApp::User", "required": true}
						}
					}
				}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User", "Group"],
						"resourceTypes": ["Document"]
					}
				},
				"edit": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					}
				},
				"manage_docs": {
					"memberOf": []
				},
				"delete": {
					"memberOf": [{"id": "manage_docs"}],
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					}
				}
			}
		}
	}`
	s, err := NewFromJSON([]byte(src))
	if err != nil {
		t.Fatalf("NewFromJSON: %v", err)
	}
	return s
}

func collectEntityTypes(seq func(func(types.EntityType) bool)) []types.EntityType {
	var out []types.EntityType
	for et := range seq {
		out = append(out, et)
	}
	slices.Sort(out)
	return out
}

func collectEntityUIDs(seq func(func(types.EntityUID) bool)) []string {
	var out []string
	for uid := range seq {
		out = append(out, uid.ID.String())
	}
	slices.Sort(out)
	return out
}

func TestEntityTypes(t *testing.T) {
	s := newTestSchema(t)
	got := collectEntityTypes(s.EntityTypes())
	want := []types.EntityType{"MyApp::Document", "MyApp::Group", "MyApp::User"}
	if !slices.Equal(got, want) {
		t.Errorf("EntityTypes() = %v, want %v", got, want)
	}
}

func TestActions(t *testing.T) {
	s := newTestSchema(t)
	got := collectEntityUIDs(s.Actions())
	// view, edit, delete are leaf actions; manage_docs is a group
	want := []string{"delete", "edit", "view"}
	if !slices.Equal(got, want) {
		t.Errorf("Actions() = %v, want %v", got, want)
	}
}

func TestActionGroups(t *testing.T) {
	s := newTestSchema(t)
	got := collectEntityUIDs(s.ActionGroups())
	want := []string{"manage_docs"}
	if !slices.Equal(got, want) {
		t.Errorf("ActionGroups() = %v, want %v", got, want)
	}
}

func TestPrincipals(t *testing.T) {
	s := newTestSchema(t)
	got := collectEntityTypes(s.Principals())
	want := []types.EntityType{"MyApp::Group", "MyApp::User"}
	if !slices.Equal(got, want) {
		t.Errorf("Principals() = %v, want %v", got, want)
	}
}

func TestResources(t *testing.T) {
	s := newTestSchema(t)
	got := collectEntityTypes(s.Resources())
	want := []types.EntityType{"MyApp::Document"}
	if !slices.Equal(got, want) {
		t.Errorf("Resources() = %v, want %v", got, want)
	}
}

func TestPrincipalsForAction(t *testing.T) {
	s := newTestSchema(t)

	viewAction := types.EntityUID{Type: "MyApp::Action", ID: "view"}
	iter, ok := s.PrincipalsForAction(viewAction)
	if !ok {
		t.Fatal("PrincipalsForAction returned false for known action")
	}
	got := collectEntityTypes(iter)
	want := []types.EntityType{"MyApp::Group", "MyApp::User"}
	if !slices.Equal(got, want) {
		t.Errorf("PrincipalsForAction(view) = %v, want %v", got, want)
	}

	// Unknown action
	_, ok = s.PrincipalsForAction(types.EntityUID{Type: "MyApp::Action", ID: "unknown"})
	if ok {
		t.Error("PrincipalsForAction should return false for unknown action")
	}
}

func TestResourcesForAction(t *testing.T) {
	s := newTestSchema(t)

	editAction := types.EntityUID{Type: "MyApp::Action", ID: "edit"}
	iter, ok := s.ResourcesForAction(editAction)
	if !ok {
		t.Fatal("ResourcesForAction returned false")
	}
	got := collectEntityTypes(iter)
	want := []types.EntityType{"MyApp::Document"}
	if !slices.Equal(got, want) {
		t.Errorf("ResourcesForAction(edit) = %v, want %v", got, want)
	}
}

func TestActionsForPrincipalAndResource(t *testing.T) {
	s := newTestSchema(t)

	// User + Document = view, edit, delete
	got := collectEntityUIDs(s.ActionsForPrincipalAndResource("MyApp::User", "MyApp::Document"))
	want := []string{"delete", "edit", "view"}
	if !slices.Equal(got, want) {
		t.Errorf("ActionsForPrincipalAndResource(User, Document) = %v, want %v", got, want)
	}

	// Group + Document = view only
	got = collectEntityUIDs(s.ActionsForPrincipalAndResource("MyApp::Group", "MyApp::Document"))
	want = []string{"view"}
	if !slices.Equal(got, want) {
		t.Errorf("ActionsForPrincipalAndResource(Group, Document) = %v, want %v", got, want)
	}

	// Nonexistent combination = empty
	got = collectEntityUIDs(s.ActionsForPrincipalAndResource("MyApp::User", "MyApp::User"))
	if len(got) != 0 {
		t.Errorf("ActionsForPrincipalAndResource(User, User) = %v, want empty", got)
	}
}

func TestAncestors(t *testing.T) {
	s := newTestSchema(t)

	iter, ok := s.Ancestors("MyApp::User")
	if !ok {
		t.Fatal("Ancestors returned false for known type")
	}
	got := collectEntityTypes(iter)
	want := []types.EntityType{"MyApp::Group"}
	if !slices.Equal(got, want) {
		t.Errorf("Ancestors(User) = %v, want %v", got, want)
	}

	// Group has no ancestors
	iter, ok = s.Ancestors("MyApp::Group")
	if !ok {
		t.Fatal("Ancestors returned false for Group")
	}
	got = collectEntityTypes(iter)
	if len(got) != 0 {
		t.Errorf("Ancestors(Group) = %v, want empty", got)
	}

	// Unknown type
	_, ok = s.Ancestors("MyApp::Unknown")
	if ok {
		t.Error("Ancestors should return false for unknown type")
	}
}

func TestActionEntities(t *testing.T) {
	s := newTestSchema(t)
	em := s.ActionEntities()

	// Should have 4 entries: view, edit, delete, manage_docs
	if len(em) != 4 {
		t.Errorf("ActionEntities has %d entries, want 4", len(em))
	}

	// delete should have manage_docs as parent
	deleteUID := types.EntityUID{Type: "MyApp::Action", ID: "delete"}
	deleteEntity, ok := em.Get(deleteUID)
	if !ok {
		t.Fatal("ActionEntities missing delete action")
	}
	manageDocs := types.EntityUID{Type: "MyApp::Action", ID: "manage_docs"}
	if !deleteEntity.Parents.Contains(manageDocs) {
		t.Error("delete action should have manage_docs as parent")
	}
}

func TestRequestEnvs(t *testing.T) {
	s := newTestSchema(t)
	var envs []RequestEnv
	for env := range s.RequestEnvs() {
		envs = append(envs, env)
	}

	// view: User×Document + Group×Document = 2
	// edit: User×Document = 1
	// delete: User×Document = 1
	// Total = 4
	if len(envs) != 4 {
		t.Errorf("RequestEnvs has %d entries, want 4", len(envs))
	}
}

func TestActionInfo(t *testing.T) {
	s := newTestSchema(t)

	viewAction := types.EntityUID{Type: "MyApp::Action", ID: "view"}
	info, ok := s.ActionInfo(viewAction)
	if !ok {
		t.Fatal("ActionInfo returned false for known action")
	}
	if len(info.PrincipalTypes) != 2 {
		t.Errorf("view has %d principal types, want 2", len(info.PrincipalTypes))
	}

	_, ok = s.ActionInfo(types.EntityUID{Type: "MyApp::Action", ID: "nope"})
	if ok {
		t.Error("ActionInfo should return false for unknown action")
	}
}

func TestEntityTypeInfoFor(t *testing.T) {
	s := newTestSchema(t)

	info, ok := s.EntityTypeInfoFor("MyApp::User")
	if !ok {
		t.Fatal("EntityTypeInfoFor returned false for User")
	}
	if _, hasName := info.Attributes["name"]; !hasName {
		t.Error("User should have 'name' attribute")
	}

	_, ok = s.EntityTypeInfoFor("MyApp::Nonexistent")
	if ok {
		t.Error("EntityTypeInfoFor should return false for unknown type")
	}
}

func TestEmptySchema(t *testing.T) {
	s, err := NewFromJSON([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}

	// All iterators should yield nothing
	count := 0
	for range s.EntityTypes() {
		count++
	}
	if count != 0 {
		t.Errorf("empty schema EntityTypes yielded %d items", count)
	}

	for range s.Actions() {
		t.Error("empty schema Actions yielded an item")
	}
	for range s.Principals() {
		t.Error("empty schema Principals yielded an item")
	}
	for range s.Resources() {
		t.Error("empty schema Resources yielded an item")
	}
	for range s.RequestEnvs() {
		t.Error("empty schema RequestEnvs yielded an item")
	}

	em := s.ActionEntities()
	if len(em) != 0 {
		t.Errorf("empty schema ActionEntities has %d entries", len(em))
	}
}

func TestMultiNamespaceSchema(t *testing.T) {
	src := `{
		"Auth": {
			"entityTypes": {"User": {}},
			"actions": {
				"login": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["User"]
					}
				}
			}
		},
		"Docs": {
			"entityTypes": {"File": {}},
			"actions": {
				"read": {
					"appliesTo": {
						"principalTypes": ["Auth::User"],
						"resourceTypes": ["File"]
					}
				}
			}
		}
	}`

	s, err := NewFromJSON([]byte(src))
	if err != nil {
		t.Fatal(err)
	}

	entityTypes := collectEntityTypes(s.EntityTypes())
	if len(entityTypes) != 2 {
		t.Errorf("multi-ns EntityTypes = %v, want 2 entries", entityTypes)
	}

	// Auth::User should be a principal in both namespaces' actions
	principals := collectEntityTypes(s.Principals())
	if !slices.Contains(principals, types.EntityType("Auth::User")) {
		t.Errorf("Auth::User not in principals: %v", principals)
	}

	// Docs::read should apply to Auth::User + Docs::File
	readAction := types.EntityUID{Type: "Docs::Action", ID: "read"}
	info, ok := s.ActionInfo(readAction)
	if !ok {
		t.Fatal("Docs::Action::read not found")
	}
	if !slices.Contains(info.PrincipalTypes, types.EntityType("Auth::User")) {
		t.Errorf("read action principals = %v, want Auth::User", info.PrincipalTypes)
	}
	if !slices.Contains(info.ResourceTypes, types.EntityType("Docs::File")) {
		t.Errorf("read action resources = %v, want Docs::File", info.ResourceTypes)
	}
}
