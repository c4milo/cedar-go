package parser_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go/internal/parser"
	"github.com/cedar-policy/cedar-go/internal/testutil"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
)

func TestParseTemplate(t *testing.T) {
	t.Parallel()
	parseTests := []struct {
		Name             string
		Text             string
		ExpectedTemplate *ast.Template
	}{
		{
			"permit with principal slot",
			`@id("template1")
permit (
    principal == ?principal,
    action,
    resource
);`,
			ast.PermitTemplate("template1").Annotate("id", "template1").PrincipalEqSlot(),
		},
		{
			"permit with resource slot",
			`@id("template2")
permit (
    principal,
    action,
    resource == ?resource
);`,
			ast.PermitTemplate("template2").Annotate("id", "template2").ResourceEqSlot(),
		},
		{
			"permit with both slots",
			`@id("template3")
permit (
    principal == ?principal,
    action,
    resource == ?resource
);`,
			ast.PermitTemplate("template3").Annotate("id", "template3").PrincipalEqSlot().ResourceEqSlot(),
		},
		{
			"forbid with principal in slot",
			`@id("template4")
forbid (
    principal in ?principal,
    action,
    resource
);`,
			ast.ForbidTemplate("template4").Annotate("id", "template4").PrincipalInSlot(),
		},
		{
			"permit with resource in slot",
			`@id("template5")
permit (
    principal,
    action,
    resource in ?resource
);`,
			ast.PermitTemplate("template5").Annotate("id", "template5").ResourceInSlot(),
		},
		{
			"template with specific action",
			`@id("view_template")
permit (
    principal == ?principal,
    action == Action::"view",
    resource == ?resource
);`,
			ast.PermitTemplate("view_template").
				Annotate("id", "view_template").
				PrincipalEqSlot().
				ActionEq(types.EntityUID{Type: "Action", ID: "view"}).
				ResourceEqSlot(),
		},
		{
			"template with condition",
			`@id("conditional_template")
permit (
    principal == ?principal,
    action,
    resource
)
when { context.authenticated == true };`,
			ast.PermitTemplate("conditional_template").
				Annotate("id", "conditional_template").
				PrincipalEqSlot().
				When(ast.Context().Access("authenticated").Equal(ast.True())),
		},
		{
			"template with multiple annotations",
			`@id("annotated_template")
@description("A template with annotations")
permit (
    principal == ?principal,
    action,
    resource
);`,
			ast.PermitTemplate("annotated_template").
				Annotate("id", "annotated_template").
				Annotate("description", "A template with annotations").
				PrincipalEqSlot(),
		},
		{
			"template without id annotation",
			`permit (
    principal == ?principal,
    action,
    resource
);`,
			ast.PermitTemplate("").PrincipalEqSlot(),
		},
	}

	for _, tt := range parseTests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			var template parser.Template
			testutil.OK(t, template.UnmarshalCedar([]byte(tt.Text)))
			template.Position = ast.Position{}
			testutil.Equals(t, &template, (*parser.Template)(tt.ExpectedTemplate))
		})
	}
}

func TestTemplateRoundTrip(t *testing.T) {
	t.Parallel()
	roundTripTests := []struct {
		Name     string
		Template *ast.Template
		Expected string
	}{
		{
			"principal eq slot",
			ast.PermitTemplate("test1").Annotate("id", "test1").PrincipalEqSlot(),
			`@id("test1")
permit (
    principal == ?principal,
    action,
    resource
);`,
		},
		{
			"resource eq slot",
			ast.PermitTemplate("test2").Annotate("id", "test2").ResourceEqSlot(),
			`@id("test2")
permit (
    principal,
    action,
    resource == ?resource
);`,
		},
		{
			"both slots",
			ast.PermitTemplate("test3").Annotate("id", "test3").PrincipalEqSlot().ResourceEqSlot(),
			`@id("test3")
permit (
    principal == ?principal,
    action,
    resource == ?resource
);`,
		},
		{
			"principal in slot",
			ast.ForbidTemplate("test4").Annotate("id", "test4").PrincipalInSlot(),
			`@id("test4")
forbid (
    principal in ?principal,
    action,
    resource
);`,
		},
		{
			"resource in slot",
			ast.PermitTemplate("test5").Annotate("id", "test5").ResourceInSlot(),
			`@id("test5")
permit (
    principal,
    action,
    resource in ?resource
);`,
		},
		{
			"with action eq",
			ast.PermitTemplate("test6").
				Annotate("id", "test6").
				PrincipalEqSlot().
				ActionEq(types.EntityUID{Type: "Action", ID: "view"}).
				ResourceEqSlot(),
			`@id("test6")
permit (
    principal == ?principal,
    action == Action::"view",
    resource == ?resource
);`,
		},
		{
			"with condition",
			ast.PermitTemplate("test7").
				Annotate("id", "test7").
				PrincipalEqSlot().
				When(ast.True()),
			`@id("test7")
permit (
    principal == ?principal,
    action,
    resource
)
when { true };`,
		},
	}

	for _, tt := range roundTripTests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			// Marshal
			var buf bytes.Buffer
			(*parser.Template)(tt.Template).MarshalCedar(&buf)

			testutil.Equals(t, buf.String(), tt.Expected)

			// Unmarshal back and verify
			var parsed parser.Template
			testutil.OK(t, parsed.UnmarshalCedar(buf.Bytes()))
			parsed.Position = ast.Position{}
			testutil.Equals(t, &parsed, (*parser.Template)(tt.Template))
		})
	}
}

func TestParseTemplateSlice(t *testing.T) {
	t.Parallel()

	templateStr := []byte(`@id("template1")
permit (
    principal == ?principal,
    action,
    resource
);
@id("template2")
forbid (
    principal,
    action,
    resource == ?resource
);`)

	var templates parser.TemplateSlice
	testutil.OK(t, templates.UnmarshalCedar(templateStr))

	testutil.Equals(t, len(templates), 2)

	// Check first template
	templates[0].Position = ast.Position{}
	expected1 := ast.PermitTemplate("template1").Annotate("id", "template1").PrincipalEqSlot()
	testutil.Equals(t, templates[0], (*parser.Template)(expected1))

	// Check second template
	templates[1].Position = ast.Position{}
	expected2 := ast.ForbidTemplate("template2").Annotate("id", "template2").ResourceEqSlot()
	testutil.Equals(t, templates[1], (*parser.Template)(expected2))
}

func TestTemplateParseErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		in              string
		outErrSubstring string
	}{
		{
			"wrong principal slot",
			`permit (principal == ?resource, action, resource);`,
			"expected ?principal slot",
		},
		{
			"wrong resource slot",
			`permit (principal, action, resource == ?principal);`,
			"expected ?resource slot",
		},
		{
			"invalid slot in action",
			`permit (principal, action == ?action, resource);`,
			"expected ident",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var template parser.Template
			err := template.UnmarshalCedar([]byte(tt.in))
			testutil.Error(t, err)
			testutil.FatalIf(t, !strings.Contains(err.Error(), tt.outErrSubstring), "got %v want substring %v", err.Error(), tt.outErrSubstring)
		})
	}
}

func TestTemplateLinking(t *testing.T) {
	t.Parallel()

	// Create a template
	template := ast.PermitTemplate("viewer_template").
		PrincipalEqSlot().
		ActionEq(types.EntityUID{Type: "Action", ID: "view"}).
		ResourceEqSlot()

	// Link the template
	alice := types.EntityUID{Type: "User", ID: "alice"}
	photo := types.EntityUID{Type: "Photo", ID: "vacation.jpg"}

	policy, err := template.Link("alice_can_view_photo", map[ast.SlotID]types.EntityUID{
		ast.SlotPrincipal: alice,
		ast.SlotResource:  photo,
	})
	testutil.OK(t, err)

	// Verify the linked policy
	testutil.Equals(t, policy.Effect, ast.EffectPermit)

	// Marshal and verify output
	var buf bytes.Buffer
	(*parser.Policy)(policy).MarshalCedar(&buf)

	expected := `permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"vacation.jpg"
);`
	testutil.Equals(t, buf.String(), expected)
}

func TestTemplateLinkMissingSlot(t *testing.T) {
	t.Parallel()

	template := ast.PermitTemplate("test").
		PrincipalEqSlot().
		ResourceEqSlot()

	// Only provide principal, missing resource
	alice := types.EntityUID{Type: "User", ID: "alice"}
	_, err := template.Link("test_link", map[ast.SlotID]types.EntityUID{
		ast.SlotPrincipal: alice,
	})
	testutil.Error(t, err)
	testutil.FatalIf(t, !strings.Contains(err.Error(), "missing value for slot"), "got %v want substring %v", err.Error(), "missing value for slot")
}

func TestTemplateSet(t *testing.T) {
	t.Parallel()

	ts := ast.NewTemplateSet()

	// Add templates
	template1 := ast.PermitTemplate("view_template").
		PrincipalEqSlot().
		ActionEq(types.EntityUID{Type: "Action", ID: "view"}).
		ResourceEqSlot()

	template2 := ast.ForbidTemplate("deny_template").
		PrincipalEqSlot().
		ResourceEqSlot()

	testutil.OK(t, ts.AddTemplate(template1))
	testutil.OK(t, ts.AddTemplate(template2))
	testutil.Equals(t, ts.Len(), 2)

	// Retrieve template
	retrieved, ok := ts.GetTemplate("view_template")
	testutil.Equals(t, ok, true)
	testutil.Equals(t, retrieved.ID, "view_template")

	// Link template
	alice := types.EntityUID{Type: "User", ID: "alice"}
	photo := types.EntityUID{Type: "Photo", ID: "vacation.jpg"}

	err := ts.Link("view_template", "alice_view_photo", map[ast.SlotID]types.EntityUID{
		ast.SlotPrincipal: alice,
		ast.SlotResource:  photo,
	})
	testutil.OK(t, err)
	testutil.Equals(t, ts.LinkCount(), 1)

	// Retrieve linked policy
	linkedPolicy, ok := ts.GetLinkedPolicy("alice_view_photo")
	testutil.Equals(t, ok, true)
	testutil.Equals(t, linkedPolicy.Effect, ast.EffectPermit)

	// Remove link
	testutil.Equals(t, ts.RemoveLink("alice_view_photo"), true)
	testutil.Equals(t, ts.LinkCount(), 0)

	// Remove template
	testutil.Equals(t, ts.RemoveTemplate("view_template"), true)
	testutil.Equals(t, ts.Len(), 1)
}

// TestParseTemplateAllScopeVariations covers all scope variations for templates
func TestParseTemplateAllScopeVariations(t *testing.T) {
	t.Parallel()

	alice := types.EntityUID{Type: "User", ID: "alice"}
	viewAction := types.EntityUID{Type: "Action", ID: "view"}
	editAction := types.EntityUID{Type: "Action", ID: "edit"}
	photo := types.EntityUID{Type: "Photo", ID: "photo1"}
	album := types.EntityUID{Type: "Album", ID: "album1"}

	tests := []struct {
		name     string
		input    string
		expected *ast.Template
	}{
		// Principal variations with concrete entities (no slots)
		{
			"principal eq entity",
			`permit (principal == User::"alice", action, resource == ?resource);`,
			func() *ast.Template {
				t := ast.PermitTemplate("").ResourceEqSlot()
				t.Principal = ast.ScopeTypeEq{Entity: alice}
				return t
			}(),
		},
		{
			"principal in entity",
			`permit (principal in User::"alice", action, resource == ?resource);`,
			func() *ast.Template {
				t := ast.PermitTemplate("").ResourceEqSlot()
				t.Principal = ast.ScopeTypeIn{Entity: alice}
				return t
			}(),
		},
		{
			"principal is type",
			`permit (principal is User, action, resource == ?resource);`,
			func() *ast.Template {
				t := ast.PermitTemplate("").ResourceEqSlot()
				t.Principal = ast.ScopeTypeIs{Type: "User"}
				return t
			}(),
		},
		{
			"principal is type in entity",
			`permit (principal is User in User::"alice", action, resource == ?resource);`,
			func() *ast.Template {
				t := ast.PermitTemplate("").ResourceEqSlot()
				t.Principal = ast.ScopeTypeIsIn{Type: "User", Entity: alice}
				return t
			}(),
		},
		// Resource variations with concrete entities (no slots)
		{
			"resource eq entity",
			`permit (principal == ?principal, action, resource == Photo::"photo1");`,
			func() *ast.Template {
				t := ast.PermitTemplate("").PrincipalEqSlot()
				t.Resource = ast.ScopeTypeEq{Entity: photo}
				return t
			}(),
		},
		{
			"resource in entity",
			`permit (principal == ?principal, action, resource in Album::"album1");`,
			func() *ast.Template {
				t := ast.PermitTemplate("").PrincipalEqSlot()
				t.Resource = ast.ScopeTypeIn{Entity: album}
				return t
			}(),
		},
		{
			"resource is type",
			`permit (principal == ?principal, action, resource is Photo);`,
			func() *ast.Template {
				t := ast.PermitTemplate("").PrincipalEqSlot()
				t.Resource = ast.ScopeTypeIs{Type: "Photo"}
				return t
			}(),
		},
		{
			"resource is type in entity",
			`permit (principal == ?principal, action, resource is Photo in Album::"album1");`,
			func() *ast.Template {
				t := ast.PermitTemplate("").PrincipalEqSlot()
				t.Resource = ast.ScopeTypeIsIn{Type: "Photo", Entity: album}
				return t
			}(),
		},
		// Action variations
		{
			"action in entity",
			`permit (principal == ?principal, action in Action::"view", resource == ?resource);`,
			func() *ast.Template {
				t := ast.PermitTemplate("").PrincipalEqSlot().ResourceEqSlot()
				t.Action = ast.ScopeTypeIn{Entity: viewAction}
				return t
			}(),
		},
		{
			"action in set",
			`permit (principal == ?principal, action in [Action::"view", Action::"edit"], resource == ?resource);`,
			func() *ast.Template {
				t := ast.PermitTemplate("").PrincipalEqSlot().ResourceEqSlot()
				t.Action = ast.ScopeTypeInSet{Entities: []types.EntityUID{viewAction, editAction}}
				return t
			}(),
		},
		// Conditions
		{
			"with unless condition",
			`permit (principal == ?principal, action, resource)
unless { context.restricted };`,
			ast.PermitTemplate("").PrincipalEqSlot().Unless(ast.Context().Access("restricted")),
		},
		{
			"with when and unless conditions",
			`permit (principal == ?principal, action, resource)
when { context.authenticated }
unless { context.restricted };`,
			ast.PermitTemplate("").PrincipalEqSlot().
				When(ast.Context().Access("authenticated")).
				Unless(ast.Context().Access("restricted")),
		},
		// All scopes as "all"
		{
			"all scopes wildcard",
			`permit ( principal, action, resource );`,
			ast.PermitTemplate(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var template parser.Template
			testutil.OK(t, template.UnmarshalCedar([]byte(tt.input)))
			template.Position = ast.Position{}
			testutil.Equals(t, &template, (*parser.Template)(tt.expected))
		})
	}
}

// TestTemplateMarshalNonSlotScopes covers marshaling templates with non-slot scopes
func TestTemplateMarshalNonSlotScopes(t *testing.T) {
	t.Parallel()

	alice := types.EntityUID{Type: "User", ID: "alice"}
	photo := types.EntityUID{Type: "Photo", ID: "photo1"}

	tests := []struct {
		name     string
		template *ast.Template
		expected string
	}{
		{
			"principal eq entity with resource slot",
			func() *ast.Template {
				t := ast.PermitTemplate("").ResourceEqSlot()
				t.Principal = ast.ScopeTypeEq{Entity: alice}
				return t
			}(),
			`permit (
    principal == User::"alice",
    action,
    resource == ?resource
);`,
		},
		{
			"resource eq entity with principal slot",
			func() *ast.Template {
				t := ast.PermitTemplate("").PrincipalEqSlot()
				t.Resource = ast.ScopeTypeEq{Entity: photo}
				return t
			}(),
			`permit (
    principal == ?principal,
    action,
    resource == Photo::"photo1"
);`,
		},
		{
			"all scopes wildcard",
			ast.PermitTemplate(""),
			`permit ( principal, action, resource );`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			(*parser.Template)(tt.template).MarshalCedar(&buf)
			testutil.Equals(t, buf.String(), tt.expected)
		})
	}
}

// TestTemplateParseMoreErrors covers additional error cases
func TestTemplateParseMoreErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		in              string
		outErrSubstring string
	}{
		{
			"wrong slot in principal in",
			`permit (principal in ?resource, action, resource);`,
			"expected ?principal slot",
		},
		{
			"wrong slot in resource in",
			`permit (principal, action, resource in ?principal);`,
			"expected ?resource slot",
		},
		{
			"tokenize error in template",
			"\x00permit (principal, action, resource);",
			"invalid character",
		},
		{
			"missing semicolon",
			`permit (principal == ?principal, action, resource)`,
			"want ;",
		},
		{
			"missing close paren",
			`permit (principal == ?principal, action, resource;`,
			"want )",
		},
		{
			"invalid effect",
			`allow (principal == ?principal, action, resource);`,
			"unexpected effect",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var template parser.Template
			err := template.UnmarshalCedar([]byte(tt.in))
			testutil.Error(t, err)
			testutil.FatalIf(t, !strings.Contains(err.Error(), tt.outErrSubstring), "got %v want substring %v", err.Error(), tt.outErrSubstring)
		})
	}
}

// TestTemplateSliceParseErrors covers error cases for template slice parsing
func TestTemplateSliceParseErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		in              string
		outErrSubstring string
	}{
		{
			"tokenize error",
			"\x00permit (principal, action, resource);",
			"invalid character",
		},
		{
			"parse error in second template",
			`permit (principal == ?principal, action, resource);
permit (principal == ?resource, action, resource);`,
			"expected ?principal slot",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var templates parser.TemplateSlice
			err := templates.UnmarshalCedar([]byte(tt.in))
			testutil.Error(t, err)
			testutil.FatalIf(t, !strings.Contains(err.Error(), tt.outErrSubstring), "got %v want substring %v", err.Error(), tt.outErrSubstring)
		})
	}
}

// TestTemplateSlotInIsIn covers the "is Type in ?slot" case
func TestTemplateSlotInIsIn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{
			"principal is type in slot",
			`permit (principal is User in ?principal, action, resource == ?resource);`,
		},
		{
			"resource is type in slot",
			`permit (principal == ?principal, action, resource is Photo in ?resource);`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var template parser.Template
			testutil.OK(t, template.UnmarshalCedar([]byte(tt.input)))
			// Just verify it parses without error - the slot should be recorded
			testutil.FatalIf(t, len(template.Slots) == 0, "expected slots to be recorded")
		})
	}
}

// TestTemplateSlotInIsInErrors covers error cases for "is Type in ?slot"
func TestTemplateSlotInIsInErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		input           string
		outErrSubstring string
	}{
		{
			"wrong slot in principal is in",
			`permit (principal is User in ?resource, action, resource);`,
			"expected ?principal slot",
		},
		{
			"wrong slot in resource is in",
			`permit (principal, action, resource is Photo in ?principal);`,
			"expected ?resource slot",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var template parser.Template
			err := template.UnmarshalCedar([]byte(tt.input))
			testutil.Error(t, err)
			testutil.FatalIf(t, !strings.Contains(err.Error(), tt.outErrSubstring), "got %v want substring %v", err.Error(), tt.outErrSubstring)
		})
	}
}

// TestTemplateParseErrorPaths covers additional error paths for full coverage
func TestTemplateParseErrorPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		input           string
		outErrSubstring string
	}{
		// Principal scope errors
		{
			"principal missing keyword",
			`permit (User::"alice", action, resource);`,
			"want principal",
		},
		{
			"principal eq invalid entity",
			`permit (principal == invalid, action, resource);`,
			"want ::",
		},
		{
			"principal in invalid entity",
			`permit (principal in invalid, action, resource == ?resource);`,
			"want ::",
		},
		{
			"principal is invalid path",
			`permit (principal is 123, action, resource == ?resource);`,
			"expected ident",
		},
		{
			"principal is in invalid entity",
			`permit (principal is User in invalid, action, resource == ?resource);`,
			"want ::",
		},
		// Action scope errors
		{
			"action missing keyword",
			`permit (principal == ?principal, User::"alice", resource);`,
			"want action",
		},
		{
			"action eq invalid entity",
			`permit (principal == ?principal, action == invalid, resource);`,
			"want ::",
		},
		{
			"action in invalid entity",
			`permit (principal == ?principal, action in invalid, resource == ?resource);`,
			"want ::",
		},
		{
			"action in set invalid",
			`permit (principal == ?principal, action in [invalid], resource == ?resource);`,
			"want ::",
		},
		// Resource scope errors
		{
			"resource missing keyword",
			`permit (principal == ?principal, action, User::"alice");`,
			"want resource",
		},
		{
			"resource eq invalid entity",
			`permit (principal == ?principal, action, resource == invalid);`,
			"want ::",
		},
		{
			"resource in invalid entity",
			`permit (principal == ?principal, action, resource in invalid);`,
			"want ::",
		},
		{
			"resource is invalid path",
			`permit (principal == ?principal, action, resource is 123);`,
			"expected ident",
		},
		{
			"resource is in invalid entity",
			`permit (principal == ?principal, action, resource is Photo in invalid);`,
			"want ::",
		},
		// Condition errors
		{
			"when invalid expression",
			`permit (principal == ?principal, action, resource) when { invalid_func() };`,
			"is not a function",
		},
		{
			"unless invalid expression",
			`permit (principal == ?principal, action, resource) unless { invalid_func() };`,
			"is not a function",
		},
		// Missing comma between scopes
		{
			"missing comma after principal",
			`permit (principal == ?principal action, resource);`,
			"want ,",
		},
		{
			"missing comma after action",
			`permit (principal == ?principal, action resource);`,
			"want ,",
		},
		// Missing open paren
		{
			"missing open paren",
			`permit principal == ?principal, action, resource);`,
			"want (",
		},
		// Annotation errors
		{
			"annotations error propagates",
			`@123("bad")
permit (principal == ?principal, action, resource);`,
			"expected ident",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var template parser.Template
			err := template.UnmarshalCedar([]byte(tt.input))
			testutil.Error(t, err)
			testutil.FatalIf(t, !strings.Contains(err.Error(), tt.outErrSubstring), "got %v want substring %v", err.Error(), tt.outErrSubstring)
		})
	}
}

// TestTokenizeSlotInvalid tests the TokenUnknown case for ? without valid identifier
func TestTokenizeSlotInvalid(t *testing.T) {
	t.Parallel()

	// Test ? followed by non-identifier
	input := `permit (principal == ?123, action, resource);`
	var template parser.Template
	err := template.UnmarshalCedar([]byte(input))
	testutil.Error(t, err)
	// The ? followed by 123 will be tokenized as TokenUnknown
}
