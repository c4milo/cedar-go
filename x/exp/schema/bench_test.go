package schema

import (
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

func benchSchema(b *testing.B) *Schema {
	b.Helper()
	src := `{
		"MyApp": {
			"entityTypes": {
				"User": {
					"memberOfTypes": ["Group"],
					"shape": {
						"type": "Record",
						"attributes": {
							"name": {"type": "String", "required": true},
							"email": {"type": "String", "required": true}
						}
					}
				},
				"Group": {},
				"Document": {
					"shape": {
						"type": "Record",
						"attributes": {
							"owner": {"type": "Entity", "name": "MyApp::User", "required": true},
							"title": {"type": "String", "required": true}
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
				"delete": {
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
		b.Fatalf("NewFromJSON: %v", err)
	}
	return s
}

func benchEntities(b *testing.B) types.EntityMap {
	b.Helper()
	em := make(types.EntityMap, 100)
	for i := range 50 {
		uid := types.NewEntityUID("MyApp::User", types.String("user"+string(rune('0'+i/10))+string(rune('0'+i%10))))
		em[uid] = types.Entity{
			UID:        uid,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.NewRecord(types.RecordMap{"name": types.String("Name"), "email": types.String("e@x.com")}),
		}
	}
	for i := range 50 {
		uid := types.NewEntityUID("MyApp::Document", types.String("doc"+string(rune('0'+i/10))+string(rune('0'+i%10))))
		em[uid] = types.Entity{
			UID:        uid,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.NewRecord(types.RecordMap{"owner": types.NewEntityUID("MyApp::User", "user00"), "title": types.String("Title")}),
		}
	}
	return em
}

func BenchmarkQueryAction(b *testing.B) {
	s := benchSchema(b)
	entities := benchEntities(b)
	ps, _ := cedar.NewPolicySetFromBytes("b.cedar", []byte(`permit (principal, action, resource);`))
	alice := types.NewEntityUID("MyApp::User", "user00")
	doc := types.NewEntityUID("MyApp::Document", "doc00")
	req := ActionQueryRequest{Principal: alice, Resource: doc, Context: types.NewRecord(nil)}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, _ = s.QueryAction(ps, entities, req)
	}
}

func BenchmarkQueryPrincipal(b *testing.B) {
	s := benchSchema(b)
	entities := benchEntities(b)
	ps, _ := cedar.NewPolicySetFromBytes("b.cedar", []byte(`permit (principal, action, resource);`))
	doc := types.NewEntityUID("MyApp::Document", "doc00")
	viewAction := types.NewEntityUID("MyApp::Action", "view")
	req := PrincipalQueryRequest{PrincipalType: "MyApp::User", Action: viewAction, Resource: doc, Context: types.NewRecord(nil)}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, _ = s.QueryPrincipal(ps, entities, req)
	}
}

func BenchmarkQueryResource(b *testing.B) {
	s := benchSchema(b)
	entities := benchEntities(b)
	ps, _ := cedar.NewPolicySetFromBytes("b.cedar", []byte(`permit (principal, action, resource);`))
	alice := types.NewEntityUID("MyApp::User", "user00")
	viewAction := types.NewEntityUID("MyApp::Action", "view")
	req := ResourceQueryRequest{Principal: alice, Action: viewAction, ResourceType: "MyApp::Document", Context: types.NewRecord(nil)}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, _ = s.QueryResource(ps, entities, req)
	}
}

func BenchmarkQueryActionDiff(b *testing.B) {
	s := benchSchema(b)
	entities := benchEntities(b)
	basePolicies, _ := cedar.NewPolicySetFromBytes("b.cedar", []byte(`permit (principal, action == MyApp::Action::"view", resource);`))
	extraPS, _ := cedar.NewPolicySetFromBytes("e.cedar", []byte(`permit (principal, action == MyApp::Action::"edit", resource);`))
	var extraPolicy *cedar.Policy
	for _, p := range extraPS.All() {
		extraPolicy = p
		break
	}
	alice := types.NewEntityUID("MyApp::User", "user00")
	doc := types.NewEntityUID("MyApp::Document", "doc00")
	req := ActionQueryRequest{Principal: alice, Resource: doc, Context: types.NewRecord(nil)}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, _ = s.QueryActionDiff(basePolicies, extraPolicy, entities, req)
	}
}

func BenchmarkNewFromJSON(b *testing.B) {
	src := []byte(`{
		"MyApp": {
			"entityTypes": {
				"User": {"memberOfTypes": ["Group"], "shape": {"type": "Record", "attributes": {"name": {"type": "String"}}}},
				"Group": {},
				"Document": {"shape": {"type": "Record", "attributes": {"owner": {"type": "Entity", "name": "MyApp::User"}}}}
			},
			"actions": {
				"view": {"appliesTo": {"principalTypes": ["User","Group"], "resourceTypes": ["Document"]}},
				"edit": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Document"]}},
				"delete": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Document"]}}
			}
		}
	}`)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, _ = NewFromJSON(src)
	}
}

func BenchmarkActionsForPrincipalAndResource(b *testing.B) {
	s := benchSchema(b)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		for range s.ActionsForPrincipalAndResource("MyApp::User", "MyApp::Document") {
		}
	}
}

func BenchmarkTypesMatch(b *testing.B) {
	expected := RecordType{Attributes: map[string]AttributeType{
		"name":  {Type: StringType{}, Required: true},
		"email": {Type: StringType{}, Required: true},
		"age":   {Type: LongType{}, Required: false},
	}}
	actual := RecordType{Attributes: map[string]AttributeType{
		"name":  {Type: StringType{}, Required: true},
		"email": {Type: StringType{}, Required: true},
		"age":   {Type: LongType{}, Required: true},
	}}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		TypesMatch(expected, actual)
	}
}
