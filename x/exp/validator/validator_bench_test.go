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

package validator_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/validator"
)

// BenchmarkValidatePolicies benchmarks basic policy validation
func BenchmarkValidatePolicies(b *testing.B) {
	schemaJSON := `{
		"entityTypes": {
			"User": { "memberOfTypes": ["UserGroup"] },
			"UserGroup": {},
			"Document": { "memberOfTypes": ["Folder"] },
			"Folder": {}
		},
		"actions": {
			"read": {
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["Document"]
				}
			},
			"write": {
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["Document"]
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		b.Fatal(err)
	}

	policyStr := `permit(principal == User::"alice", action == Action::"read", resource == Document::"doc1");`
	ps, err := cedar.NewPolicySetFromBytes("", []byte(policyStr))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidatePolicies(s, ps)
	}
}

// BenchmarkValidatePolicyCount benchmarks validation with varying policy counts
func BenchmarkValidatePolicyCount(b *testing.B) {
	schemaJSON := `{
		"entityTypes": {
			"User": {},
			"Document": {}
		},
		"actions": {
			"read": {
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["Document"]
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		b.Fatal(err)
	}

	policyCounts := []int{1, 10, 50, 100, 500}

	for _, count := range policyCounts {
		b.Run(fmt.Sprintf("policies=%d", count), func(b *testing.B) {
			var sb strings.Builder
			for i := range count {
				fmt.Fprintf(&sb, `permit(principal == User::"user%d", action == Action::"read", resource == Document::"doc%d");`+"\n", i, i)
			}

			ps, err := cedar.NewPolicySetFromBytes("", []byte(sb.String()))
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				validator.ValidatePolicies(s, ps)
			}
		})
	}
}

// BenchmarkValidateComplexConditions benchmarks validation with complex when/unless clauses
func BenchmarkValidateComplexConditions(b *testing.B) {
	schemaJSON := `{
		"entityTypes": {
			"User": {
				"shape": {
					"type": "Record",
					"attributes": {
						"department": { "type": "String", "required": true },
						"level": { "type": "Long", "required": true },
						"active": { "type": "Boolean", "required": true }
					}
				}
			},
			"Document": {
				"shape": {
					"type": "Record",
					"attributes": {
						"classification": { "type": "String", "required": true },
						"owner": { "type": "Entity", "name": "User", "required": true }
					}
				}
			}
		},
		"actions": {
			"read": {
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["Document"],
					"context": {
						"type": "Record",
						"attributes": {
							"authenticated": { "type": "Boolean", "required": true },
							"ip_address": { "type": "Extension", "name": "ipaddr", "required": false }
						}
					}
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		b.Fatal(err)
	}

	policyStr := `
		permit(
			principal,
			action == Action::"read",
			resource
		) when {
			principal.active &&
			principal.level > 5 &&
			principal.department == "engineering" &&
			resource.classification != "top-secret" &&
			context.authenticated
		} unless {
			resource.owner == principal
		};
	`

	ps, err := cedar.NewPolicySetFromBytes("", []byte(policyStr))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidatePolicies(s, ps)
	}
}

// BenchmarkValidateEntityTypes benchmarks validation with varying entity type counts
func BenchmarkValidateEntityTypes(b *testing.B) {
	for _, count := range []int{2, 10, 50, 100} {
		b.Run(fmt.Sprintf("types=%d", count), func(b *testing.B) {
			runEntityTypesBenchmark(b, count)
		})
	}
}

func runEntityTypesBenchmark(b *testing.B, count int) {
	schemaJSON := buildEntityTypesSchema(count)
	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		b.Fatal(err)
	}

	policyStr := `permit(principal == Type0::"e1", action == Action::"action0", resource == Type1::"e2");`
	ps, err := cedar.NewPolicySetFromBytes("", []byte(policyStr))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidatePolicies(s, ps)
	}
}

func buildEntityTypesSchema(count int) string {
	var sb strings.Builder
	sb.WriteString(`{"entityTypes": {`)
	for i := range count {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `"Type%d": {}`, i)
	}
	sb.WriteString(`}, "actions": {"action0": {"appliesTo": {"principalTypes": ["Type0"], "resourceTypes": ["Type1"]}}}}`)
	return sb.String()
}

// BenchmarkValidateActions benchmarks validation with varying action counts
func BenchmarkValidateActions(b *testing.B) {
	for _, count := range []int{1, 10, 50, 100} {
		b.Run(fmt.Sprintf("actions=%d", count), func(b *testing.B) {
			runActionsBenchmark(b, count)
		})
	}
}

func runActionsBenchmark(b *testing.B, count int) {
	schemaJSON := buildActionsSchema(count)
	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		b.Fatal(err)
	}

	policyStr := `permit(principal, action, resource);`
	ps, err := cedar.NewPolicySetFromBytes("", []byte(policyStr))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidatePolicies(s, ps)
	}
}

func buildActionsSchema(count int) string {
	var sb strings.Builder
	sb.WriteString(`{"entityTypes": {"User": {}, "Document": {}}, "actions": {`)
	for i := range count {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `"action%d": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Document"]}}`, i)
	}
	sb.WriteString(`}}`)
	return sb.String()
}

// BenchmarkValidateImpossiblePolicy benchmarks detection of impossible policies
func BenchmarkValidateImpossiblePolicy(b *testing.B) {
	schemaJSON := `{
		"entityTypes": {
			"User": {},
			"Admin": {},
			"Document": {},
			"Secret": {}
		},
		"actions": {
			"read": {
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["Document"]
				}
			},
			"admin": {
				"appliesTo": {
					"principalTypes": ["Admin"],
					"resourceTypes": ["Secret"]
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		b.Fatal(err)
	}

	// Policy that references wrong type for action
	policyStr := `permit(principal == Admin::"admin1", action == Action::"read", resource == Secret::"s1");`
	ps, err := cedar.NewPolicySetFromBytes("", []byte(policyStr))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := validator.ValidatePolicies(s, ps)
		if result.Valid {
			b.Fatal("expected validation to fail")
		}
	}
}

// BenchmarkValidateAllocs measures memory allocations during validation
func BenchmarkValidateAllocs(b *testing.B) {
	schemaJSON := `{
		"entityTypes": {
			"User": { "memberOfTypes": ["UserGroup"] },
			"UserGroup": {},
			"Document": {}
		},
		"actions": {
			"read": {
				"appliesTo": {
					"principalTypes": ["User"],
					"resourceTypes": ["Document"]
				}
			}
		}
	}`

	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		b.Fatal(err)
	}

	policyStr := `
		permit(principal in UserGroup::"admins", action == Action::"read", resource)
		when { true }
		unless { false };
	`
	ps, err := cedar.NewPolicySetFromBytes("", []byte(policyStr))
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidatePolicies(s, ps)
	}
}

// BenchmarkValidateMemberOfTypes benchmarks validation with deep memberOf hierarchies
func BenchmarkValidateMemberOfTypes(b *testing.B) {
	for _, depth := range []int{1, 5, 10, 20} {
		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			runMemberOfTypesBenchmark(b, depth)
		})
	}
}

func runMemberOfTypesBenchmark(b *testing.B, depth int) {
	schemaJSON := buildMemberOfSchema(depth)
	s, err := schema.NewFromJSON([]byte(schemaJSON))
	if err != nil {
		b.Fatal(err)
	}

	policyStr := fmt.Sprintf(`permit(principal in Type%d::"root", action, resource);`, depth-1)
	ps, err := cedar.NewPolicySetFromBytes("", []byte(policyStr))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidatePolicies(s, ps)
	}
}

func buildMemberOfSchema(depth int) string {
	var sb strings.Builder
	sb.WriteString(`{"entityTypes": {`)
	for i := range depth {
		if i > 0 {
			sb.WriteString(",")
		}
		if i == depth-1 {
			fmt.Fprintf(&sb, `"Type%d": {}`, i)
		} else {
			fmt.Fprintf(&sb, `"Type%d": {"memberOfTypes": ["Type%d"]}`, i, i+1)
		}
	}
	sb.WriteString(`}, "actions": {"action0": {"appliesTo": {"principalTypes": ["Type0"], "resourceTypes": ["Type0"]}}}}`)
	return sb.String()
}
