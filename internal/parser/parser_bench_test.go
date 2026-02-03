package parser_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/cedar-policy/cedar-go/internal/parser"
)

// Benchmark parsing a simple policy
func BenchmarkParseSimplePolicy(b *testing.B) {
	policyText := []byte(`permit (principal, action, resource);`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var p parser.Policy
		if err := p.UnmarshalCedar(policyText); err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark parsing policy with scope constraints
func BenchmarkParseScopedPolicy(b *testing.B) {
	policyText := []byte(`
		permit (
			principal == User::"alice",
			action == Action::"read",
			resource == Document::"doc1"
		);
	`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var p parser.Policy
		if err := p.UnmarshalCedar(policyText); err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark parsing policy with conditions
func BenchmarkParseConditionPolicy(b *testing.B) {
	policyText := []byte(`
		permit (
			principal,
			action == Action::"read",
			resource
		) when {
			context.authenticated == true &&
			context.role == "admin"
		} unless {
			resource.classification == "top-secret"
		};
	`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var p parser.Policy
		if err := p.UnmarshalCedar(policyText); err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark parsing policy with annotations
func BenchmarkParseAnnotatedPolicy(b *testing.B) {
	policyText := []byte(`
		@id("policy1")
		@description("Allow admins to read documents")
		@author("security-team")
		permit (
			principal,
			action == Action::"read",
			resource
		) when {
			principal.role == "admin"
		};
	`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var p parser.Policy
		if err := p.UnmarshalCedar(policyText); err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark parsing complex expressions
func BenchmarkParseComplexExpression(b *testing.B) {
	policyText := []byte(`
		permit (
			principal,
			action,
			resource
		) when {
			if context.emergency then
				true
			else
				(context.level > 5 && context.clearance >= resource.requiredClearance) ||
				principal in Group::"superusers"
		};
	`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var p parser.Policy
		if err := p.UnmarshalCedar(policyText); err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark parsing policy set with increasing policy count
func BenchmarkParsePolicySet(b *testing.B) {
	policyCounts := []int{1, 10, 100}

	for _, count := range policyCounts {
		b.Run(fmt.Sprintf("policies=%d", count), func(b *testing.B) {
			var buf bytes.Buffer
			for i := range count {
				fmt.Fprintf(&buf, `
					@id("policy%d")
					permit (
						principal == User::"user%d",
						action == Action::"read",
						resource == Document::"doc%d"
					);
				`, i, i, i)
			}
			policyText := buf.Bytes()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var ps parser.PolicySlice
				if err := ps.UnmarshalCedar(policyText); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Benchmark tokenization
func BenchmarkTokenize(b *testing.B) {
	policyText := []byte(`
		permit (
			principal == User::"alice",
			action == Action::"read",
			resource == Document::"doc1"
		) when {
			context.authenticated == true &&
			context.role == "admin"
		};
	`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parser.Tokenize(policyText)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark marshaling (serialization)
func BenchmarkMarshalPolicy(b *testing.B) {
	policyText := []byte(`
		@id("policy1")
		permit (
			principal == User::"alice",
			action == Action::"read",
			resource == Document::"doc1"
		) when {
			context.authenticated == true
		};
	`)

	var p parser.Policy
	if err := p.UnmarshalCedar(policyText); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		p.MarshalCedar(&buf)
	}
}

// Benchmark round-trip (parse + marshal)
func BenchmarkRoundTrip(b *testing.B) {
	policyText := []byte(`
		permit (
			principal == User::"alice",
			action == Action::"read",
			resource == Document::"doc1"
		) when {
			context.authenticated == true
		};
	`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var p parser.Policy
		if err := p.UnmarshalCedar(policyText); err != nil {
			b.Fatal(err)
		}
		var buf bytes.Buffer
		p.MarshalCedar(&buf)
	}
}

// Benchmark template parsing
func BenchmarkParseTemplate(b *testing.B) {
	templateText := []byte(`
		@id("viewer_template")
		permit (
			principal == ?principal,
			action == Action::"view",
			resource == ?resource
		);
	`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var t parser.Template
		if err := t.UnmarshalCedar(templateText); err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark parsing with extension functions
func BenchmarkParseExtensionFunctions(b *testing.B) {
	policyText := []byte(`
		permit (
			principal,
			action,
			resource
		) when {
			ip("192.168.1.1").isInRange(ip("192.168.0.0/16")) &&
			decimal("3.14159").lessThan(decimal("4.0"))
		};
	`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var p parser.Policy
		if err := p.UnmarshalCedar(policyText); err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark memory allocations during parsing
func BenchmarkParseAllocs(b *testing.B) {
	policyText := []byte(`
		permit (
			principal == User::"alice",
			action == Action::"read",
			resource == Document::"doc1"
		) when {
			context.authenticated == true
		};
	`)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var p parser.Policy
		if err := p.UnmarshalCedar(policyText); err != nil {
			b.Fatal(err)
		}
	}
}
