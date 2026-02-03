package cedar

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go/types"
)

//go:embed corpus-tests.tar.gz
var benchCorpusArchive []byte

// BenchmarkCorpusAuthorize benchmarks authorization against the Cedar test corpus.
// This measures real-world performance with production-like policies.
func BenchmarkCorpusAuthorize(b *testing.B) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(benchCorpusArchive))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = gzipReader.Close() }()

	buf, err := io.ReadAll(gzipReader)
	if err != nil {
		b.Fatal(err)
	}

	bufReader := bytes.NewReader(buf)
	archiveReader := tar.NewReader(bufReader)

	type filePointer struct {
		Position int64
		Size     int64
	}
	files := make(map[string]filePointer)
	var testFiles []string

	for file, err := archiveReader.Next(); err == nil; file, err = archiveReader.Next() {
		if file.Typeflag != tar.TypeReg {
			continue
		}
		cursor, _ := bufReader.Seek(0, io.SeekCurrent)
		files[file.Name] = filePointer{Position: cursor, Size: file.Size}

		if strings.HasSuffix(file.Name, ".json") && !strings.HasSuffix(file.Name, ".entities.json") {
			testFiles = append(testFiles, file.Name)
		}
	}

	getFile := func(path string) ([]byte, error) {
		fp, ok := files[path]
		if !ok {
			return nil, fmt.Errorf("file not found: %s", path)
		}
		content := make([]byte, fp.Size)
		_, err := bufReader.ReadAt(content, fp.Position)
		return content, err
	}

	// Use first 10 test files for benchmarking
	maxTests := min(10, len(testFiles))

	type corpusTestFile struct {
		Policies string `json:"policies"`
		Entities string `json:"entities"`
		Requests []struct {
			Principal types.EntityUID `json:"principal"`
			Action    types.EntityUID `json:"action"`
			Resource  types.EntityUID `json:"resource"`
			Context   Record          `json:"context"`
		} `json:"requests"`
	}

	for i := range maxTests {
		testFile := testFiles[i]
		b.Run(testFile, func(b *testing.B) {
			testContent, err := getFile(testFile)
			if err != nil {
				b.Fatal(err)
			}

			var tt corpusTestFile
			if err := json.Unmarshal(testContent, &tt); err != nil {
				b.Fatal(err)
			}

			entitiesContent, err := getFile(tt.Entities)
			if err != nil {
				b.Fatal(err)
			}

			var entities EntityMap
			if err := json.Unmarshal(entitiesContent, &entities); err != nil {
				b.Fatal(err)
			}

			policyContent, err := getFile(tt.Policies)
			if err != nil {
				b.Fatal(err)
			}

			ps, err := NewPolicySetFromBytes("policy.cedar", policyContent)
			if err != nil {
				b.Fatal(err)
			}

			if len(tt.Requests) == 0 {
				b.Skip("no requests")
			}

			req := Request{
				Principal: tt.Requests[0].Principal,
				Action:    tt.Requests[0].Action,
				Resource:  tt.Requests[0].Resource,
				Context:   tt.Requests[0].Context,
			}

			// Pre-build index
			ps.BuildIndex()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Authorize(ps, entities, req)
			}
		})
	}
}

// Benchmark authorization with varying policy set sizes
func BenchmarkAuthorize(b *testing.B) {
	// Create a simple permit policy
	ps := NewPolicySet()
	var policy Policy
	if err := policy.UnmarshalCedar([]byte(`
		permit (
			principal == User::"alice",
			action == Action::"read",
			resource == Document::"doc1"
		);
	`)); err != nil {
		b.Fatal(err)
	}
	ps.Add(PolicyID("policy0"), &policy)

	entities := types.EntityMap{}
	req := Request{
		Principal: NewEntityUID("User", "alice"),
		Action:    NewEntityUID("Action", "read"),
		Resource:  NewEntityUID("Document", "doc1"),
		Context:   types.Record{},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Authorize(ps, entities, req)
	}
}

// unindexedPolicySet wraps a PolicySet but forces All() iteration (no indexing)
type unindexedPolicySet struct {
	ps *PolicySet
}

func (u *unindexedPolicySet) All() iter.Seq2[PolicyID, *Policy] {
	return u.ps.All()
}

// BenchmarkAuthorizeIndexThreshold compares indexed vs unindexed at various policy counts
func BenchmarkAuthorizeIndexThreshold(b *testing.B) {
	counts := []int{51, 100, 500, 1000}

	for _, count := range counts {
		// Create policy set with exact match policies (only one will match)
		ps := NewPolicySet()
		for i := range count {
			policyText := fmt.Sprintf(`
				permit (
					principal == User::"user%d",
					action == Action::"action%d",
					resource == Document::"doc%d"
				);
			`, i, i, i)
			var policy Policy
			if err := policy.UnmarshalCedar([]byte(policyText)); err != nil {
				b.Fatal(err)
			}
			ps.Add(PolicyID(fmt.Sprintf("policy%d", i)), &policy)
		}

		entities := types.EntityMap{}
		req := Request{
			Principal: NewEntityUID("User", "user25"),
			Action:    NewEntityUID("Action", "action25"),
			Resource:  NewEntityUID("Document", "doc25"),
		}

		// Pre-build index
		ps.BuildIndex()

		// Indexed version (automatic for >50 policies)
		b.Run(fmt.Sprintf("indexed/%d", count), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Authorize(ps, entities, req)
			}
		})

		// Unindexed version - wrap to force All() iteration
		unindexed := &unindexedPolicySet{ps: ps}
		b.Run(fmt.Sprintf("unindexed/%d", count), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Authorize(unindexed, entities, req)
			}
		})
	}
}

// Benchmark with increasing policy count
func BenchmarkAuthorizePolicyCount(b *testing.B) {
	policyCounts := []int{1, 10, 100, 1000}

	for _, count := range policyCounts {
		b.Run(fmt.Sprintf("policies=%d", count), func(b *testing.B) {
			ps := NewPolicySet()

			// Add policies - only one will match
			for i := range count {
				policyText := fmt.Sprintf(`
					permit (
						principal == User::"user%d",
						action == Action::"read",
						resource == Document::"doc%d"
					);
				`, i, i)
				var policy Policy
				if err := policy.UnmarshalCedar([]byte(policyText)); err != nil {
					b.Fatal(err)
				}
				ps.Add(PolicyID(fmt.Sprintf("policy%d", i)), &policy)
			}

			entities := types.EntityMap{}
			req := Request{
				Principal: NewEntityUID("User", "user0"),
				Action:    NewEntityUID("Action", "read"),
				Resource:  NewEntityUID("Document", "doc0"),
				Context:   types.Record{},
			}

			// Pre-build index so it's not measured
			ps.BuildIndex()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Authorize(ps, entities, req)
			}
		})
	}
}

// Benchmark with entity hierarchy traversal (tests "in" operator)
func BenchmarkAuthorizeEntityHierarchy(b *testing.B) {
	depths := []int{1, 5, 10, 20}

	for _, depth := range depths {
		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			ps := NewPolicySet()
			var policy Policy
			if err := policy.UnmarshalCedar([]byte(`
				permit (
					principal in Group::"root",
					action == Action::"read",
					resource
				);
			`)); err != nil {
				b.Fatal(err)
			}
			ps.Add(PolicyID("policy0"), &policy)

			// Create entity hierarchy: user -> group1 -> group2 -> ... -> root
			entities := types.EntityMap{}
			prevUID := NewEntityUID("Group", "root")
			entities = entities.Upsert(types.Entity{UID: prevUID})

			for i := depth - 1; i >= 1; i-- {
				uid := NewEntityUID("Group", String(fmt.Sprintf("group%d", i)))
				entities = entities.Upsert(types.Entity{
					UID:     uid,
					Parents: NewEntityUIDSet(prevUID),
				})
				prevUID = uid
			}

			userUID := NewEntityUID("User", "alice")
			entities = entities.Upsert(types.Entity{
				UID:     userUID,
				Parents: NewEntityUIDSet(prevUID),
			})

			req := Request{
				Principal: userUID,
				Action:    NewEntityUID("Action", "read"),
				Resource:  NewEntityUID("Document", "doc1"),
				Context:   types.Record{},
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Authorize(ps, entities, req)
			}
		})
	}
}

// Benchmark with complex conditions
func BenchmarkAuthorizeComplexConditions(b *testing.B) {
	ps := NewPolicySet()
	var policy Policy
	if err := policy.UnmarshalCedar([]byte(`
		permit (
			principal,
			action == Action::"read",
			resource
		) when {
			context.authenticated == true &&
			context.role == "admin" &&
			context.department == "engineering" &&
			resource.classification != "top-secret"
		};
	`)); err != nil {
		b.Fatal(err)
	}
	ps.Add(PolicyID("policy0"), &policy)

	entities := types.EntityMap{}
	docUID := NewEntityUID("Document", "doc1")
	entities = entities.Upsert(types.Entity{
		UID: docUID,
		Attributes: types.NewRecord(types.RecordMap{
			"classification": types.String("confidential"),
		}),
	})

	req := Request{
		Principal: NewEntityUID("User", "alice"),
		Action:    NewEntityUID("Action", "read"),
		Resource:  docUID,
		Context: types.NewRecord(types.RecordMap{
			"authenticated": types.Boolean(true),
			"role":          types.String("admin"),
			"department":    types.String("engineering"),
		}),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Authorize(ps, entities, req)
	}
}

// Benchmark forbid evaluation (tests short-circuit behavior)
func BenchmarkAuthorizeForbid(b *testing.B) {
	ps := NewPolicySet()

	// Add many permit policies
	for i := range 100 {
		var policy Policy
		if err := policy.UnmarshalCedar([]byte(`
			permit (
				principal,
				action == Action::"read",
				resource
			);
		`)); err != nil {
			b.Fatal(err)
		}
		ps.Add(PolicyID(fmt.Sprintf("permit%d", i)), &policy)
	}

	// Add one forbid policy
	var forbidPolicy Policy
	if err := forbidPolicy.UnmarshalCedar([]byte(`
		forbid (
			principal == User::"alice",
			action == Action::"read",
			resource
		);
	`)); err != nil {
		b.Fatal(err)
	}
	ps.Add(PolicyID("forbid0"), &forbidPolicy)

	entities := types.EntityMap{}
	req := Request{
		Principal: NewEntityUID("User", "alice"),
		Action:    NewEntityUID("Action", "read"),
		Resource:  NewEntityUID("Document", "doc1"),
		Context:   types.Record{},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Authorize(ps, entities, req)
	}
}

// Benchmark with attribute access
func BenchmarkAuthorizeAttributeAccess(b *testing.B) {
	attributeCounts := []int{1, 10, 50}

	for _, count := range attributeCounts {
		b.Run(fmt.Sprintf("attributes=%d", count), func(b *testing.B) {
			ps := NewPolicySet()

			// Build condition that accesses multiple attributes
			var sb strings.Builder
			sb.WriteString("context.attr0 == true")
			for i := 1; i < count; i++ {
				fmt.Fprintf(&sb, " && context.attr%d == true", i)
			}
			condition := sb.String()

			policyText := fmt.Sprintf(`
				permit (
					principal,
					action == Action::"read",
					resource
				) when { %s };
			`, condition)
			var policy Policy
			if err := policy.UnmarshalCedar([]byte(policyText)); err != nil {
				b.Fatal(err)
			}
			ps.Add(PolicyID("policy0"), &policy)

			// Build context with attributes
			contextMap := types.RecordMap{}
			for i := range count {
				contextMap[types.String(fmt.Sprintf("attr%d", i))] = types.Boolean(true)
			}

			entities := types.EntityMap{}
			req := Request{
				Principal: NewEntityUID("User", "alice"),
				Action:    NewEntityUID("Action", "read"),
				Resource:  NewEntityUID("Document", "doc1"),
				Context:   types.NewRecord(contextMap),
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Authorize(ps, entities, req)
			}
		})
	}
}

// Benchmark memory allocations
func BenchmarkAuthorizeAllocs(b *testing.B) {
	ps := NewPolicySet()
	var policy Policy
	if err := policy.UnmarshalCedar([]byte(`
		permit (
			principal == User::"alice",
			action == Action::"read",
			resource == Document::"doc1"
		);
	`)); err != nil {
		b.Fatal(err)
	}
	ps.Add(PolicyID("policy0"), &policy)

	entities := types.EntityMap{}
	req := Request{
		Principal: NewEntityUID("User", "alice"),
		Action:    NewEntityUID("Action", "read"),
		Resource:  NewEntityUID("Document", "doc1"),
		Context:   types.Record{},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Authorize(ps, entities, req)
	}
}
