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

package eval

import (
	"slices"
	"testing"

	"github.com/cedar-policy/cedar-go/internal/mapset"
	"github.com/cedar-policy/cedar-go/internal/testutil"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
)

// residualAsserter helps verify ResidualSet fields.
type residualAsserter struct {
	t      *testing.T
	result *ResidualSet
}

func assertResidualSet(t *testing.T, result *ResidualSet) *residualAsserter {
	return &residualAsserter{t: t, result: result}
}

func (a *residualAsserter) permitKinds(want []ResidualKind) *residualAsserter {
	a.t.Helper()
	got := extractKinds(a.result.Permits)
	testutil.Equals(a.t, len(got), len(want))
	for i, w := range want {
		testutil.Equals(a.t, got[i], w)
	}
	return a
}

func (a *residualAsserter) forbidKinds(want []ResidualKind) *residualAsserter {
	a.t.Helper()
	got := extractKinds(a.result.Forbids)
	testutil.Equals(a.t, len(got), len(want))
	for i, w := range want {
		testutil.Equals(a.t, got[i], w)
	}
	return a
}

func (a *residualAsserter) mustDecide(want bool) *residualAsserter {
	a.t.Helper()
	testutil.Equals(a.t, a.result.MustDecide(), want)
	return a
}

func (a *residualAsserter) decision(want types.Decision) *residualAsserter {
	a.t.Helper()
	testutil.Equals(a.t, a.result.Decision(), want)
	return a
}

func extractKinds(policies []ResidualPolicy) []ResidualKind {
	kinds := make([]ResidualKind, len(policies))
	for i, p := range policies {
		kinds[i] = p.Kind
	}
	return kinds
}

func TestResidualKindString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kind ResidualKind
		want string
	}{
		{ResidualTrue, "true"},
		{ResidualFalse, "false"},
		{ResidualVariable, "variable"},
		{ResidualError, "error"},
		{ResidualKind(99), "unknown"},
	}
	for _, tt := range tests {
		testutil.Equals(t, tt.kind.String(), tt.want)
	}
}

func TestPartialPolicySet(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	bob := types.NewEntityUID("User", "bob")
	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	tests := []struct {
		name            string
		policies        map[types.PolicyID]*ast.Policy
		env             Env
		wantPermitKinds []ResidualKind
		wantForbidKinds []ResidualKind
		wantMustDecide  bool
		wantDecision    types.Decision
	}{
		{
			name: "simple permit - true",
			policies: map[types.PolicyID]*ast.Policy{
				"p1": ast.Permit().PrincipalEq(alice),
			},
			env: Env{
				Principal: alice,
				Action:    readAction,
				Resource:  doc1,
				Context:   types.Record{},
			},
			wantPermitKinds: []ResidualKind{ResidualTrue},
			wantMustDecide:  true,
			wantDecision:    types.Allow,
		},
		{
			name: "simple permit - false",
			policies: map[types.PolicyID]*ast.Policy{
				"p1": ast.Permit().PrincipalEq(alice),
			},
			env: Env{
				Principal: bob,
				Action:    readAction,
				Resource:  doc1,
				Context:   types.Record{},
			},
			wantPermitKinds: []ResidualKind{ResidualFalse},
			wantMustDecide:  false,
		},
		{
			name: "permit with variable principal",
			policies: map[types.PolicyID]*ast.Policy{
				"p1": ast.Permit().PrincipalEq(alice),
			},
			env: Env{
				Principal: Variable("principal"),
				Action:    readAction,
				Resource:  doc1,
				Context:   types.Record{},
			},
			wantPermitKinds: []ResidualKind{ResidualVariable},
			wantMustDecide:  false,
		},
		{
			name: "forbid trumps permit",
			policies: map[types.PolicyID]*ast.Policy{
				"p1": ast.Permit(),
				"f1": ast.Forbid(),
			},
			env: Env{
				Principal: alice,
				Action:    readAction,
				Resource:  doc1,
				Context:   types.Record{},
			},
			wantPermitKinds: []ResidualKind{ResidualTrue},
			wantForbidKinds: []ResidualKind{ResidualTrue},
			wantMustDecide:  true,
			wantDecision:    types.Deny,
		},
		{
			name: "permit with variable forbid - no decision",
			policies: map[types.PolicyID]*ast.Policy{
				"p1": ast.Permit(),
				"f1": ast.Forbid().When(ast.Context().Access("blocked").Equal(ast.True())),
			},
			env: Env{
				Principal: alice,
				Action:    readAction,
				Resource:  doc1,
				Context: types.NewRecord(types.RecordMap{
					"blocked": Variable("blocked"),
				}),
			},
			wantPermitKinds: []ResidualKind{ResidualTrue},
			wantForbidKinds: []ResidualKind{ResidualVariable},
			wantMustDecide:  false,
		},
		{
			name: "permit with error condition",
			policies: map[types.PolicyID]*ast.Policy{
				"p1": ast.Permit().When(ast.Long(42).GreaterThan(ast.String("invalid"))),
			},
			env: Env{
				Principal: alice,
				Action:    readAction,
				Resource:  doc1,
				Context:   types.Record{},
			},
			wantPermitKinds: []ResidualKind{ResidualError},
			wantMustDecide:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := PartialPolicySet(tt.env, tt.policies)
			a := assertResidualSet(t, result).mustDecide(tt.wantMustDecide)
			if len(tt.wantPermitKinds) > 0 {
				a.permitKinds(tt.wantPermitKinds)
			}
			if len(tt.wantForbidKinds) > 0 {
				a.forbidKinds(tt.wantForbidKinds)
			}
			if tt.wantMustDecide {
				a.decision(tt.wantDecision)
			}
		})
	}
}

func TestResidualSetHelpers(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	policies := map[types.PolicyID]*ast.Policy{
		"permit-true":  ast.Permit(),
		"permit-var":   ast.Permit().When(ast.Context().Access("x").Equal(ast.True())),
		"forbid-true":  ast.Forbid().ResourceEq(types.NewEntityUID("Document", "secret")),
		"forbid-var":   ast.Forbid().When(ast.Context().Access("y").Equal(ast.True())),
		"permit-false": ast.Permit().PrincipalEq(types.NewEntityUID("User", "nobody")),
	}

	env := Env{
		Principal: alice,
		Action:    readAction,
		Resource:  doc1,
		Context: types.NewRecord(types.RecordMap{
			"x": Variable("x"),
			"y": Variable("y"),
		}),
	}

	result := PartialPolicySet(env, policies)

	// Test TruePermits
	truePermits := result.TruePermits()
	testutil.Equals(t, len(truePermits), 1)
	testutil.Equals(t, truePermits[0].PolicyID, types.PolicyID("permit-true"))

	// Test VariablePermits
	varPermits := result.VariablePermits()
	testutil.Equals(t, len(varPermits), 1)
	testutil.Equals(t, varPermits[0].PolicyID, types.PolicyID("permit-var"))

	// Test TrueForbids (forbid-true is false because resource doesn't match)
	trueForbids := result.TrueForbids()
	testutil.Equals(t, len(trueForbids), 0)

	// Test VariableForbids
	varForbids := result.VariableForbids()
	testutil.Equals(t, len(varForbids), 1)
	testutil.Equals(t, varForbids[0].PolicyID, types.PolicyID("forbid-var"))

	// Test AllVariables - the AST sees "context" as the variable reference
	// (the internal variable markers like Variable("x") are in the env, not AST)
	allVars := result.AllVariables()
	testutil.Equals(t, len(allVars), 1) // "context" is the variable in the AST
}

func TestResidualPolicyVariables(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	policies := map[types.PolicyID]*ast.Policy{
		"p1": ast.Permit().When(
			ast.Context().Access("level").GreaterThan(ast.Long(5)).And(
				ast.Context().Access("approved").Equal(ast.True()),
			),
		),
	}

	env := Env{
		Principal: alice,
		Action:    readAction,
		Resource:  doc1,
		Context: types.NewRecord(types.RecordMap{
			"level":    Variable("level"),
			"approved": Variable("approved"),
		}),
	}

	result := PartialPolicySet(env, policies)

	testutil.Equals(t, len(result.Permits), 1)
	testutil.Equals(t, result.Permits[0].Kind, ResidualVariable)
	// The AST variable is "context" - the internal Variable markers are in the env
	testutil.Equals(t, len(result.Permits[0].Variables), 1)
}

func TestResidualPolicyMultipleVariables(t *testing.T) {
	t.Parallel()

	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	// Policy with variable principal and variable in condition
	policies := map[types.PolicyID]*ast.Policy{
		"p1": ast.Permit().
			PrincipalEq(types.NewEntityUID("User", "alice")).
			When(ast.Context().Access("level").GreaterThan(ast.Long(5))),
	}

	env := Env{
		Principal: Variable("principal"),
		Action:    readAction,
		Resource:  doc1,
		Context: types.NewRecord(types.RecordMap{
			"level": Variable("level"),
		}),
	}

	result := PartialPolicySet(env, policies)

	testutil.Equals(t, len(result.Permits), 1)
	testutil.Equals(t, result.Permits[0].Kind, ResidualVariable)
	// Variables: "principal" (from scope) and "context" (from AST)
	testutil.Equals(t, len(result.Permits[0].Variables), 2)
}

func TestIgnoreValue(t *testing.T) {
	t.Parallel()

	ignoreVal := Ignore()
	testutil.Equals(t, IsIgnore(ignoreVal), true)
	testutil.Equals(t, IsIgnore(types.True), false)
	testutil.Equals(t, IsIgnore(types.NewEntityUID("Test", "1")), false)
}

func TestResidualWithValueContainingVariable(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	// Policy with context containing nested variable in record
	policies := map[types.PolicyID]*ast.Policy{
		"p1": ast.Permit().When(ast.Context().Access("meta").Access("level").Equal(ast.Long(5))),
	}

	env := Env{
		Principal: alice,
		Action:    readAction,
		Resource:  doc1,
		Context: types.NewRecord(types.RecordMap{
			"meta": types.NewRecord(types.RecordMap{
				"level": Variable("level"),
			}),
		}),
	}

	result := PartialPolicySet(env, policies)
	testutil.Equals(t, result.Permits[0].Kind, ResidualVariable)
}

func TestResidualWithSetContainingVariable(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	// Policy with variable set in context
	policies := map[types.PolicyID]*ast.Policy{
		"p1": ast.Permit().When(ast.Context().Access("tags").Contains(ast.String("admin"))),
	}

	env := Env{
		Principal: alice,
		Action:    readAction,
		Resource:  doc1,
		Context: types.NewRecord(types.RecordMap{
			"tags": Variable("tags"),
		}),
	}

	result := PartialPolicySet(env, policies)
	testutil.Equals(t, result.Permits[0].Kind, ResidualVariable)
}

func TestResidualDecisionWithNoPolicies(t *testing.T) {
	t.Parallel()

	result := &ResidualSet{
		Permits: []ResidualPolicy{},
		Forbids: []ResidualPolicy{},
	}

	if result.MustDecide() {
		t.Error("Expected MustDecide to be false with no policies")
	}
}

func TestResidualDecisionWithOnlyFalsePermit(t *testing.T) {
	t.Parallel()

	result := &ResidualSet{
		Permits: []ResidualPolicy{
			{Kind: ResidualFalse, PolicyID: "p1"},
		},
		Forbids: []ResidualPolicy{},
	}

	testutil.Equals(t, result.MustDecide(), false)
}

func TestPartialEvalWithBinaryOperators(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	tests := []struct {
		name   string
		policy *ast.Policy
	}{
		{
			name:   "and operator",
			policy: ast.Permit().When(ast.True().And(ast.Context().Access("flag"))),
		},
		{
			name:   "or operator",
			policy: ast.Permit().When(ast.False().Or(ast.Context().Access("flag"))),
		},
		{
			name:   "equals operator",
			policy: ast.Permit().When(ast.Context().Access("count").Equal(ast.Long(5))),
		},
		{
			name:   "not equals operator",
			policy: ast.Permit().When(ast.Context().Access("count").NotEqual(ast.Long(5))),
		},
		{
			name:   "less than",
			policy: ast.Permit().When(ast.Context().Access("count").LessThan(ast.Long(10))),
		},
		{
			name:   "less than or equal",
			policy: ast.Permit().When(ast.Context().Access("count").LessThanOrEqual(ast.Long(10))),
		},
		{
			name:   "greater than",
			policy: ast.Permit().When(ast.Context().Access("count").GreaterThan(ast.Long(0))),
		},
		{
			name:   "greater than or equal",
			policy: ast.Permit().When(ast.Context().Access("count").GreaterThanOrEqual(ast.Long(0))),
		},
		{
			name:   "add",
			policy: ast.Permit().When(ast.Context().Access("a").Add(ast.Context().Access("b")).Equal(ast.Long(10))),
		},
		{
			name:   "sub",
			policy: ast.Permit().When(ast.Context().Access("a").Subtract(ast.Context().Access("b")).Equal(ast.Long(0))),
		},
		{
			name:   "mult",
			policy: ast.Permit().When(ast.Context().Access("a").Multiply(ast.Long(2)).Equal(ast.Long(10))),
		},
		{
			name:   "contains",
			policy: ast.Permit().When(ast.Context().Access("list").Contains(ast.Long(1))),
		},
		{
			name:   "containsAll",
			policy: ast.Permit().When(ast.Context().Access("list").ContainsAll(ast.Set(ast.Long(1), ast.Long(2)))),
		},
		{
			name:   "containsAny",
			policy: ast.Permit().When(ast.Context().Access("list").ContainsAny(ast.Set(ast.Long(1), ast.Long(9)))),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policies := map[types.PolicyID]*ast.Policy{"p1": tc.policy}

			env := Env{
				Principal: alice,
				Action:    readAction,
				Resource:  doc1,
				Context: types.NewRecord(types.RecordMap{
					"flag":  Variable("flag"),
					"count": Variable("count"),
					"a":     Variable("a"),
					"b":     Variable("b"),
					"list":  Variable("list"),
				}),
			}

			result := PartialPolicySet(env, policies)
			testutil.Equals(t, len(result.Permits), 1)
		})
	}
}

func TestPartialEvalWithUnaryOperators(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	tests := []struct {
		name   string
		policy *ast.Policy
	}{
		{
			name:   "not operator",
			policy: ast.Permit().When(ast.Not(ast.Context().Access("blocked"))),
		},
		{
			name:   "negate operator",
			policy: ast.Permit().When(ast.Negate(ast.Context().Access("score")).LessThan(ast.Long(0))),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policies := map[types.PolicyID]*ast.Policy{"p1": tc.policy}

			env := Env{
				Principal: alice,
				Action:    readAction,
				Resource:  doc1,
				Context: types.NewRecord(types.RecordMap{
					"blocked": Variable("blocked"),
					"score":   Variable("score"),
				}),
			}

			result := PartialPolicySet(env, policies)
			testutil.Equals(t, len(result.Permits), 1)
		})
	}
}

func TestPartialEvalWithTagOperators(t *testing.T) {
	t.Parallel()

	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	t.Run("hasTag", func(t *testing.T) {
		policies := map[types.PolicyID]*ast.Policy{
			"p1": ast.Permit().When(
				ast.Principal().HasTag(ast.String("role")),
			),
		}

		env := Env{
			Principal: Variable("principal"),
			Action:    readAction,
			Resource:  doc1,
			Context:   types.Record{},
		}

		result := PartialPolicySet(env, policies)
		testutil.Equals(t, len(result.Permits), 1)
		testutil.Equals(t, result.Permits[0].Kind, ResidualVariable)
	})

	t.Run("getTag", func(t *testing.T) {
		policies := map[types.PolicyID]*ast.Policy{
			"p1": ast.Permit().When(
				ast.Principal().GetTag(ast.String("role")).Equal(ast.String("admin")),
			),
		}

		env := Env{
			Principal: Variable("principal"),
			Action:    readAction,
			Resource:  doc1,
			Context:   types.Record{},
		}

		result := PartialPolicySet(env, policies)
		testutil.Equals(t, len(result.Permits), 1)
		testutil.Equals(t, result.Permits[0].Kind, ResidualVariable)
	})
}

func TestResidualWithFalseUnlessCondition(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	// Policy with unless condition that evaluates to true (meaning deny)
	policies := map[types.PolicyID]*ast.Policy{
		"p1": ast.Permit().Unless(ast.True()),
	}

	env := Env{
		Principal: alice,
		Action:    readAction,
		Resource:  doc1,
		Context:   types.Record{},
	}

	result := PartialPolicySet(env, policies)
	testutil.Equals(t, len(result.Permits), 1)
	testutil.Equals(t, result.Permits[0].Kind, ResidualFalse)
}

func TestResidualWithTrueUnlessCondition(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	// Policy with unless condition that evaluates to false (meaning permit)
	policies := map[types.PolicyID]*ast.Policy{
		"p1": ast.Permit().Unless(ast.False()),
	}

	env := Env{
		Principal: alice,
		Action:    readAction,
		Resource:  doc1,
		Context:   types.Record{},
	}

	result := PartialPolicySet(env, policies)
	testutil.Equals(t, len(result.Permits), 1)
	testutil.Equals(t, result.Permits[0].Kind, ResidualTrue)
}

func TestResidualWithRecordContainingVariable(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	// Policy checking nested record attribute
	policies := map[types.PolicyID]*ast.Policy{
		"p1": ast.Permit().When(ast.Context().Access("config").Access("enabled").Equal(ast.True())),
	}

	env := Env{
		Principal: alice,
		Action:    readAction,
		Resource:  doc1,
		Context: types.NewRecord(types.RecordMap{
			"config": types.NewRecord(types.RecordMap{
				"enabled": Variable("enabled"),
			}),
		}),
	}

	result := PartialPolicySet(env, policies)
	testutil.Equals(t, result.Permits[0].Kind, ResidualVariable)
}

func TestResidualWithIfThenElse(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	// Policy with if-then-else containing variable
	policies := map[types.PolicyID]*ast.Policy{
		"p1": ast.Permit().When(
			ast.IfThenElse(
				ast.Context().Access("condition"),
				ast.True(),
				ast.False(),
			),
		),
	}

	env := Env{
		Principal: alice,
		Action:    readAction,
		Resource:  doc1,
		Context: types.NewRecord(types.RecordMap{
			"condition": Variable("condition"),
		}),
	}

	result := PartialPolicySet(env, policies)
	testutil.Equals(t, result.Permits[0].Kind, ResidualVariable)
}

func TestResidualWithExtensionCall(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	// Policy with IP address check
	policies := map[types.PolicyID]*ast.Policy{
		"p1": ast.Permit().When(
			ast.ExtensionCall("ip", ast.Context().Access("sourceIP")).IsIpv4(),
		),
	}

	env := Env{
		Principal: alice,
		Action:    readAction,
		Resource:  doc1,
		Context: types.NewRecord(types.RecordMap{
			"sourceIP": Variable("sourceIP"),
		}),
	}

	result := PartialPolicySet(env, policies)
	testutil.Equals(t, result.Permits[0].Kind, ResidualVariable)
}

func TestResidualWithSetLiteral(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	// Policy checking set membership with variable set element
	policies := map[types.PolicyID]*ast.Policy{
		"p1": ast.Permit().When(
			ast.Set(ast.Context().Access("role"), ast.String("user")).Contains(ast.String("admin")),
		),
	}

	env := Env{
		Principal: alice,
		Action:    readAction,
		Resource:  doc1,
		Context: types.NewRecord(types.RecordMap{
			"role": Variable("role"),
		}),
	}

	result := PartialPolicySet(env, policies)
	testutil.Equals(t, result.Permits[0].Kind, ResidualVariable)
}

func TestResidualWithRecordLiteral(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	// Policy with record literal containing variable
	policies := map[types.PolicyID]*ast.Policy{
		"p1": ast.Permit().When(
			ast.Record(ast.Pairs{{Key: "status", Value: ast.Context().Access("status")}}).Access("status").Equal(ast.String("ok")),
		),
	}

	env := Env{
		Principal: alice,
		Action:    readAction,
		Resource:  doc1,
		Context: types.NewRecord(types.RecordMap{
			"status": Variable("status"),
		}),
	}

	result := PartialPolicySet(env, policies)
	testutil.Equals(t, result.Permits[0].Kind, ResidualVariable)
}

func TestResidualWithLikeOperator(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	// Policy with like operator
	policies := map[types.PolicyID]*ast.Policy{
		"p1": ast.Permit().When(
			ast.Context().Access("name").Like(types.NewPattern("admin*")),
		),
	}

	env := Env{
		Principal: alice,
		Action:    readAction,
		Resource:  doc1,
		Context: types.NewRecord(types.RecordMap{
			"name": Variable("name"),
		}),
	}

	result := PartialPolicySet(env, policies)
	testutil.Equals(t, result.Permits[0].Kind, ResidualVariable)
}

func TestResidualWithIsOperator(t *testing.T) {
	t.Parallel()

	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	policies := map[types.PolicyID]*ast.Policy{
		"p1": ast.Permit().When(ast.Principal().Is("User")),
	}

	env := Env{
		Principal: Variable("principal"),
		Action:    readAction,
		Resource:  doc1,
		Context:   types.Record{},
	}

	result := PartialPolicySet(env, policies)
	testutil.Equals(t, result.Permits[0].Kind, ResidualVariable)
}

func TestResidualWithIsInOperator(t *testing.T) {
	t.Parallel()

	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")
	admins := types.NewEntityUID("Group", "admins")

	policies := map[types.PolicyID]*ast.Policy{
		"p1": ast.Permit().When(ast.Principal().IsIn("User", ast.Value(admins))),
	}

	env := Env{
		Principal: Variable("principal"),
		Action:    readAction,
		Resource:  doc1,
		Context:   types.Record{},
	}

	result := PartialPolicySet(env, policies)
	testutil.Equals(t, result.Permits[0].Kind, ResidualVariable)
}

func TestResidualWithHasAttribute(t *testing.T) {
	t.Parallel()

	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	policies := map[types.PolicyID]*ast.Policy{
		"p1": ast.Permit().When(ast.Principal().Has("department")),
	}

	env := Env{
		Principal: Variable("principal"),
		Action:    readAction,
		Resource:  doc1,
		Context:   types.Record{},
	}

	result := PartialPolicySet(env, policies)
	testutil.Equals(t, result.Permits[0].Kind, ResidualVariable)
}

func TestResidualWithIsEmptyOperator(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	policies := map[types.PolicyID]*ast.Policy{
		"p1": ast.Permit().When(ast.Context().Access("items").IsEmpty()),
	}

	env := Env{
		Principal: alice,
		Action:    readAction,
		Resource:  doc1,
		Context: types.NewRecord(types.RecordMap{
			"items": Variable("items"),
		}),
	}

	result := PartialPolicySet(env, policies)
	testutil.Equals(t, result.Permits[0].Kind, ResidualVariable)
}

func TestResidualWithInOperator(t *testing.T) {
	t.Parallel()

	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")
	admins := types.NewEntityUID("Group", "admins")

	policies := map[types.PolicyID]*ast.Policy{
		"p1": ast.Permit().When(ast.Principal().In(ast.Value(admins))),
	}

	env := Env{
		Principal: Variable("principal"),
		Action:    readAction,
		Resource:  doc1,
		Context:   types.Record{},
	}

	result := PartialPolicySet(env, policies)
	testutil.Equals(t, result.Permits[0].Kind, ResidualVariable)
}

func TestResidualDecisionPanic(t *testing.T) {
	t.Parallel()

	result := &ResidualSet{
		Permits: []ResidualPolicy{},
		Forbids: []ResidualPolicy{},
	}

	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when calling Decision without MustDecide")
		}
	}()

	result.Decision()
}

func TestResidualAllVariablesFromForbids(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	policies := map[types.PolicyID]*ast.Policy{
		"f1": ast.Forbid().When(ast.Context().Access("blocked").Equal(ast.True())),
	}

	env := Env{
		Principal: alice,
		Action:    readAction,
		Resource:  doc1,
		Context: types.NewRecord(types.RecordMap{
			"blocked": Variable("blocked"),
		}),
	}

	result := PartialPolicySet(env, policies)
	allVars := result.AllVariables()
	testutil.Equals(t, len(allVars), 1)
}

func TestResidualVariableActionScope(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	doc1 := types.NewEntityUID("Document", "doc1")
	readAction := types.NewEntityUID("Action", "read")

	// Policy with action constraint that requires specific action
	policies := map[types.PolicyID]*ast.Policy{
		"p1": ast.Permit().ActionEq(readAction),
	}

	env := Env{
		Principal: alice,
		Action:    Variable("action"),
		Resource:  doc1,
		Context:   types.Record{},
	}

	result := PartialPolicySet(env, policies)
	testutil.Equals(t, result.Permits[0].Kind, ResidualVariable)
	// Check that "action" is in the variables
	testutil.Equals(t, slices.Contains(result.Permits[0].Variables, types.String("action")), true)
}

func TestResidualVariableResourceScope(t *testing.T) {
	t.Parallel()

	alice := types.NewEntityUID("User", "alice")
	readAction := types.NewEntityUID("Action", "read")
	doc1 := types.NewEntityUID("Document", "doc1")

	// Policy with resource constraint that requires specific resource
	policies := map[types.PolicyID]*ast.Policy{
		"p1": ast.Permit().ResourceEq(doc1),
	}

	env := Env{
		Principal: alice,
		Action:    readAction,
		Resource:  Variable("resource"),
		Context:   types.Record{},
	}

	result := PartialPolicySet(env, policies)
	testutil.Equals(t, result.Permits[0].Kind, ResidualVariable)
	// Check that "resource" is in the variables
	testutil.Equals(t, slices.Contains(result.Permits[0].Variables, types.String("resource")), true)
}

func TestClassifyResidualWithNilPolicy(t *testing.T) {
	t.Parallel()
	kind := classifyResidual(nil)
	testutil.Equals(t, kind, ResidualFalse)
}

func TestClassifyConditionWithTrueWhen(t *testing.T) {
	t.Parallel()
	// When condition with true value should return ResidualTrue
	cond := ast.ConditionType{
		Condition: ast.ConditionWhen,
		Body:      ast.NodeValue{Value: types.Boolean(true)},
	}
	kind := classifyCondition(cond)
	testutil.Equals(t, kind, ResidualTrue)
}

func TestClassifyConditionWithFalseUnless(t *testing.T) {
	t.Parallel()
	// Unless condition with false value should return ResidualTrue (unless false = when true)
	cond := ast.ConditionType{
		Condition: ast.ConditionUnless,
		Body:      ast.NodeValue{Value: types.Boolean(false)},
	}
	kind := classifyCondition(cond)
	testutil.Equals(t, kind, ResidualTrue)
}

func TestHasVariablesWithNil(t *testing.T) {
	t.Parallel()
	result := hasVariables(nil)
	testutil.Equals(t, result, false)
}

func TestValueHasVariablesWithRecord(t *testing.T) {
	t.Parallel()
	// Record with variable
	rec := types.NewRecord(types.RecordMap{
		"user": Variable("user"),
	})
	result := valueHasVariables(rec)
	testutil.Equals(t, result, true)

	// Record without variable
	rec2 := types.NewRecord(types.RecordMap{
		"name": types.String("test"),
	})
	result2 := valueHasVariables(rec2)
	testutil.Equals(t, result2, false)
}

func TestValueHasVariablesWithSet(t *testing.T) {
	t.Parallel()
	// Set with variable
	set := types.NewSet(Variable("item"))
	result := valueHasVariables(set)
	testutil.Equals(t, result, true)

	// Set without variable
	set2 := types.NewSet(types.String("a"), types.String("b"))
	result2 := valueHasVariables(set2)
	testutil.Equals(t, result2, false)
}

func TestFindValueVariablesWithRecord(t *testing.T) {
	t.Parallel()
	var found mapset.MapSet[types.String]
	rec := types.NewRecord(types.RecordMap{
		"user": Variable("user"),
	})
	findValueVariables(&found, rec)
	testutil.Equals(t, found.Len(), 1)
}

func TestFindValueVariablesWithSet(t *testing.T) {
	t.Parallel()
	var found mapset.MapSet[types.String]
	set := types.NewSet(Variable("item"))
	findValueVariables(&found, set)
	testutil.Equals(t, found.Len(), 1)
}

func TestExtractPolicyErrorWithNoError(t *testing.T) {
	t.Parallel()
	policy := ast.Permit().When(ast.True())
	errMsg := extractPolicyError(policy)
	testutil.Equals(t, errMsg, "")
}

func TestGetTagNodeChildrenDefault(t *testing.T) {
	t.Parallel()
	// Test with a non-tag node (should return nil)
	node := ast.NodeValue{Value: types.Long(42)}
	children := getTagNodeChildren(node)
	testutil.Equals(t, children == nil, true)
}

func TestGetBinaryNodeChildrenDefault(t *testing.T) {
	t.Parallel()
	// Test with a non-binary node (should return nil)
	node := ast.NodeValue{Value: types.Long(42)}
	children := getBinaryNodeChildren(node)
	testutil.Equals(t, children == nil, true)
}

func TestClassifyResidualWithMultipleTrueConditions(t *testing.T) {
	t.Parallel()
	// Policy with multiple conditions that all evaluate to true
	policy := &ast.Policy{
		Effect:    ast.EffectPermit,
		Principal: ast.ScopeTypeAll{},
		Action:    ast.ScopeTypeAll{},
		Resource:  ast.ScopeTypeAll{},
		Conditions: []ast.ConditionType{
			{Condition: ast.ConditionWhen, Body: ast.NodeValue{Value: types.Boolean(true)}},
			{Condition: ast.ConditionWhen, Body: ast.NodeValue{Value: types.Boolean(true)}},
		},
	}
	kind := classifyResidual(policy)
	testutil.Equals(t, kind, ResidualTrue)
}

func TestClassifyConditionWithNonBooleanValue(t *testing.T) {
	t.Parallel()
	// Condition with a non-boolean value that has no variables (e.g., just a number)
	// This would hit the final return ResidualTrue path
	cond := ast.ConditionType{
		Condition: ast.ConditionWhen,
		Body:      ast.NodeValue{Value: types.Long(42)},
	}
	kind := classifyCondition(cond)
	// Non-boolean value with no variables returns true (the policy engine will evaluate it)
	testutil.Equals(t, kind, ResidualTrue)
}

func TestClassifyConditionWhenFalse(t *testing.T) {
	t.Parallel()
	// When condition with false value should return ResidualFalse
	cond := ast.ConditionType{
		Condition: ast.ConditionWhen,
		Body:      ast.NodeValue{Value: types.Boolean(false)},
	}
	kind := classifyCondition(cond)
	testutil.Equals(t, kind, ResidualFalse)
}

func TestFindNodeVariablesWithNil(t *testing.T) {
	t.Parallel()
	var found mapset.MapSet[types.String]
	findNodeVariables(&found, nil)
	testutil.Equals(t, found.Len(), 0)
}
