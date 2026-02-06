package cedar_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/ast"
	"github.com/cedar-policy/cedar-go/internal/testutil"
	"github.com/cedar-policy/cedar-go/types"
)

func TestPolicySetConcurrentReads(t *testing.T) {
	t.Parallel()

	ps := cedar.NewPolicySet()
	for i := range 100 {
		ps.Add(cedar.PolicyID(fmt.Sprintf("policy%d", i)),
			cedar.NewPolicyFromAST(ast.Permit().
				ActionEq(types.NewEntityUID("Action", cedar.String(fmt.Sprintf("action%d", i))))))
	}

	entities := cedar.EntityMap{}
	req := cedar.Request{
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "action42"),
		Resource:  types.NewEntityUID("Document", "doc1"),
	}

	// Hammer Authorize from many goroutines concurrently
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			for range 100 {
				decision, _ := cedar.Authorize(ps, entities, req)
				if decision != cedar.Allow {
					t.Error("expected Allow")
				}
			}
		})
	}
	wg.Wait()
}

func TestPolicySetConcurrentReadsDuringWrites(t *testing.T) {
	t.Parallel()

	ps := cedar.NewPolicySet()
	for i := range 50 {
		ps.Add(cedar.PolicyID(fmt.Sprintf("policy%d", i)),
			cedar.NewPolicyFromAST(ast.Permit()))
	}

	entities := cedar.EntityMap{}
	req := cedar.Request{
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "read"),
		Resource:  types.NewEntityUID("Document", "doc1"),
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Readers: continuous Authorize calls
	for range 20 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					// Should never panic, regardless of concurrent writes
					cedar.Authorize(ps, entities, req)
				}
			}
		})
	}

	// Readers: continuous Get calls
	for range 10 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					ps.Get("policy0")
				}
			}
		})
	}

	// Readers: continuous All() iteration
	for range 10 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					count := 0
					for range ps.All() {
						count++
					}
					_ = count
				}
			}
		})
	}

	// Writer: add and remove policies concurrently
	wg.Go(func() {
		for i := range 200 {
			id := cedar.PolicyID(fmt.Sprintf("concurrent%d", i))
			ps.Add(id, cedar.NewPolicyFromAST(ast.Permit()))
			if i%2 == 0 {
				ps.Remove(id)
			}
		}
		close(stop)
	})

	wg.Wait()
}

func TestPolicySetConcurrentWrites(t *testing.T) {
	t.Parallel()

	ps := cedar.NewPolicySet()

	var wg sync.WaitGroup
	// Multiple writers adding policies concurrently
	for g := range 10 {
		wg.Go(func() {
			for i := range 50 {
				id := cedar.PolicyID(fmt.Sprintf("g%d-p%d", g, i))
				ps.Add(id, cedar.NewPolicyFromAST(ast.Permit()))
			}
		})
	}
	wg.Wait()

	// All 500 policies should be present
	count := 0
	for range ps.All() {
		count++
	}
	testutil.Equals(t, count, 500)
}

func TestPolicySetSnapshotIsolation(t *testing.T) {
	t.Parallel()

	ps := cedar.NewPolicySet()
	ps.Add("original", cedar.NewPolicyFromAST(ast.Permit()))

	// Take a snapshot via All() iterator
	iter := ps.All()

	// Modify the PolicySet after obtaining the iterator
	ps.Add("added-after", cedar.NewPolicyFromAST(ast.Forbid()))
	ps.Remove("original")

	// The iterator should reflect the state at the time All() was called
	count := 0
	sawOriginal := false
	sawAdded := false
	for id := range iter {
		count++
		if id == "original" {
			sawOriginal = true
		}
		if id == "added-after" {
			sawAdded = true
		}
	}
	testutil.Equals(t, count, 1)
	testutil.Equals(t, sawOriginal, true)
	testutil.Equals(t, sawAdded, false)
}

func TestPolicySetZeroValueConcurrency(t *testing.T) {
	t.Parallel()

	// Zero-value PolicySet should be safe to use concurrently
	var ps cedar.PolicySet
	var wg sync.WaitGroup

	for range 10 {
		wg.Go(func() {
			ps.Get("nonexistent")
			for range ps.All() {
			}
		})
	}
	wg.Wait()
}

func TestPolicySetConcurrentBuildIndex(t *testing.T) {
	t.Parallel()

	ps := cedar.NewPolicySet()
	for i := range 100 {
		ps.Add(cedar.PolicyID(fmt.Sprintf("policy%d", i)),
			cedar.NewPolicyFromAST(ast.Permit()))
	}

	// Multiple goroutines calling BuildIndex concurrently
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			ps.BuildIndex()
		})
	}
	wg.Wait()
}

func TestPolicySetConcurrentAuthorizeCorrectness(t *testing.T) {
	t.Parallel()

	ps := cedar.NewPolicySet()
	// One permit policy for alice reading doc1
	ps.Add("permit-alice", cedar.NewPolicyFromAST(
		ast.Permit().
			PrincipalEq(types.NewEntityUID("User", "alice")).
			ActionEq(types.NewEntityUID("Action", "read")).
			ResourceEq(types.NewEntityUID("Document", "doc1")),
	))
	// One forbid policy for bob
	ps.Add("forbid-bob", cedar.NewPolicyFromAST(
		ast.Forbid().
			PrincipalEq(types.NewEntityUID("User", "bob")),
	))
	// Fillers to trigger indexing
	for i := range 60 {
		ps.Add(cedar.PolicyID(fmt.Sprintf("filler%d", i)),
			cedar.NewPolicyFromAST(ast.Permit().
				PrincipalEq(types.NewEntityUID("User", cedar.String(fmt.Sprintf("user%d", i)))).
				ActionEq(types.NewEntityUID("Action", cedar.String(fmt.Sprintf("action%d", i))))))
	}

	entities := cedar.EntityMap{}
	var wg sync.WaitGroup
	var aliceErrors, bobErrors atomic.Int64

	// Alice should always be allowed
	for range 50 {
		wg.Go(func() {
			for range 100 {
				decision, _ := cedar.Authorize(ps, entities, cedar.Request{
					Principal: types.NewEntityUID("User", "alice"),
					Action:    types.NewEntityUID("Action", "read"),
					Resource:  types.NewEntityUID("Document", "doc1"),
				})
				if decision != cedar.Allow {
					aliceErrors.Add(1)
				}
			}
		})
	}

	// Bob should always be denied
	for range 50 {
		wg.Go(func() {
			for range 100 {
				decision, _ := cedar.Authorize(ps, entities, cedar.Request{
					Principal: types.NewEntityUID("User", "bob"),
					Action:    types.NewEntityUID("Action", "read"),
					Resource:  types.NewEntityUID("Document", "doc1"),
				})
				if decision != cedar.Deny {
					bobErrors.Add(1)
				}
			}
		})
	}

	wg.Wait()
	testutil.Equals(t, aliceErrors.Load(), int64(0))
	testutil.Equals(t, bobErrors.Load(), int64(0))
}

func TestPolicySetConcurrentMarshal(t *testing.T) {
	t.Parallel()

	ps, err := cedar.NewPolicySetFromBytes("", []byte(`permit (principal, action, resource);`))
	testutil.OK(t, err)

	var wg sync.WaitGroup

	// Concurrent MarshalCedar
	for range 20 {
		wg.Go(func() {
			for range 100 {
				_ = ps.MarshalCedar()
			}
		})
	}

	// Concurrent MarshalJSON
	for range 20 {
		wg.Go(func() {
			for range 100 {
				_, err := ps.MarshalJSON()
				if err != nil {
					t.Error(err)
				}
			}
		})
	}

	wg.Wait()
}

// Benchmarks

func newBenchPolicySet(n int) *cedar.PolicySet {
	ps := cedar.NewPolicySet()
	for i := range n {
		ps.Add(cedar.PolicyID(fmt.Sprintf("policy%d", i)),
			cedar.NewPolicyFromAST(ast.Permit().
				PrincipalEq(types.NewEntityUID("User", cedar.String(fmt.Sprintf("user%d", i)))).
				ActionEq(types.NewEntityUID("Action", cedar.String(fmt.Sprintf("action%d", i)))).
				ResourceEq(types.NewEntityUID("Document", cedar.String(fmt.Sprintf("doc%d", i))))))
	}
	return ps
}

func BenchmarkPolicySetGet(b *testing.B) {
	ps := newBenchPolicySet(100)
	b.ResetTimer()
	for b.Loop() {
		ps.Get("policy50")
	}
}

func BenchmarkPolicySetGetParallel(b *testing.B) {
	ps := newBenchPolicySet(100)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ps.Get("policy50")
		}
	})
}

func BenchmarkPolicySetAll(b *testing.B) {
	ps := newBenchPolicySet(100)
	b.ResetTimer()
	for b.Loop() {
		for range ps.All() {
		}
	}
}

func BenchmarkPolicySetAllParallel(b *testing.B) {
	ps := newBenchPolicySet(100)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			for range ps.All() {
			}
		}
	})
}

func BenchmarkPolicySetAuthorize(b *testing.B) {
	for _, size := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("policies=%d", size), func(b *testing.B) {
			ps := newBenchPolicySet(size)
			ps.BuildIndex()
			entities := cedar.EntityMap{}
			req := cedar.Request{
				Principal: types.NewEntityUID("User", "user0"),
				Action:    types.NewEntityUID("Action", "action0"),
				Resource:  types.NewEntityUID("Document", "doc0"),
			}
			b.ResetTimer()
			for b.Loop() {
				cedar.Authorize(ps, entities, req)
			}
		})
	}
}

func BenchmarkPolicySetAuthorizeParallel(b *testing.B) {
	for _, size := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("policies=%d", size), func(b *testing.B) {
			ps := newBenchPolicySet(size)
			ps.BuildIndex()
			entities := cedar.EntityMap{}
			req := cedar.Request{
				Principal: types.NewEntityUID("User", "user0"),
				Action:    types.NewEntityUID("Action", "action0"),
				Resource:  types.NewEntityUID("Document", "doc0"),
			}
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					cedar.Authorize(ps, entities, req)
				}
			})
		})
	}
}

func BenchmarkPolicySetAdd(b *testing.B) {
	for _, size := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("existing=%d", size), func(b *testing.B) {
			ps := newBenchPolicySet(size)
			policy := cedar.NewPolicyFromAST(ast.Permit())
			b.ResetTimer()
			for i := range b.N {
				ps.Add(cedar.PolicyID(fmt.Sprintf("new%d", i)), policy)
			}
		})
	}
}

func BenchmarkPolicySetReadDuringWrite(b *testing.B) {
	ps := newBenchPolicySet(100)
	ps.BuildIndex()

	// Background writer
	stop := make(chan struct{})
	go func() {
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
				id := cedar.PolicyID(fmt.Sprintf("bg%d", i))
				ps.Add(id, cedar.NewPolicyFromAST(ast.Permit()))
				ps.Remove(id)
				i++
			}
		}
	}()

	entities := cedar.EntityMap{}
	req := cedar.Request{
		Principal: types.NewEntityUID("User", "user0"),
		Action:    types.NewEntityUID("Action", "action0"),
		Resource:  types.NewEntityUID("Document", "doc0"),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cedar.Authorize(ps, entities, req)
		}
	})
	b.StopTimer()
	close(stop)
}
