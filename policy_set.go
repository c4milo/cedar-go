// Package cedar provides an implementation of the Cedar language authorizer.
package cedar

import (
	"bytes"
	"encoding/json"
	"fmt"
	"iter"
	"maps"
	"slices"

	internaljson "github.com/cedar-policy/cedar-go/internal/json"
	"github.com/cedar-policy/cedar-go/types"
	internalast "github.com/cedar-policy/cedar-go/x/exp/ast"
)

//revive:disable-next-line:exported
type PolicyID = types.PolicyID

// PolicyMap is a map of policy IDs to policy
type PolicyMap map[PolicyID]*Policy

// All returns an iterator over the policy IDs and policies in the PolicyMap.
func (p PolicyMap) All() iter.Seq2[PolicyID, *Policy] {
	return maps.All(p)
}

// PolicySet is a set of named policies against which a request can be authorized.
type PolicySet struct {
	// policies are stored internally so we can handle performance, concurrency bookkeeping however we want
	policies PolicyMap

	// Index for fast policy lookup - lazily built on first authorization
	index      *policyIndex
	indexDirty bool // true when policies changed and index needs rebuild
}

// NewPolicySet creates a new, empty PolicySet
func NewPolicySet() *PolicySet {
	return &PolicySet{policies: PolicyMap{}, indexDirty: true}
}

// NewPolicySetFromBytes will create a PolicySet from the given text document with the given file name used in Position
// data.  If there is an error parsing the document, it will be returned.
//
// NewPolicySetFromBytes assigns default PolicyIDs to the policies contained in fileName in the format "policy<n>" where
// <n> is incremented for each new policy found in the file.
func NewPolicySetFromBytes(fileName string, document []byte) (*PolicySet, error) {
	policySlice, err := NewPolicyListFromBytes(fileName, document)
	if err != nil {
		return &PolicySet{}, err
	}
	policyMap := make(PolicyMap, len(policySlice))
	for i, p := range policySlice {
		policyID := PolicyID(fmt.Sprintf("policy%d", i))
		policyMap[policyID] = p
	}
	return &PolicySet{policies: policyMap, indexDirty: true}, nil
}

// Get returns the Policy with the given ID. If a policy with the given ID
// does not exist, nil is returned.
func (p *PolicySet) Get(policyID PolicyID) *Policy {
	return p.policies[policyID]
}

// Add inserts or updates a policy with the given ID. Returns true if a policy
// with the given ID did not already exist in the set.
func (p *PolicySet) Add(policyID PolicyID, policy *Policy) bool {
	_, exists := p.policies[policyID]
	p.policies[policyID] = policy
	p.indexDirty = true // Mark index for rebuild
	return !exists
}

// Remove removes a policy from the PolicySet. Returns true if a policy with
// the given ID already existed in the set.
func (p *PolicySet) Remove(policyID PolicyID) bool {
	_, exists := p.policies[policyID]
	delete(p.policies, policyID)
	p.indexDirty = true // Mark index for rebuild
	return exists
}

// Map returns a new PolicyMap instance of the policies in the PolicySet.
//
// Deprecated: use the iterator returned by All() like so: maps.Collect(ps.All())
func (p *PolicySet) Map() PolicyMap {
	return maps.Clone(p.policies)
}

// MarshalCedar emits a concatenated Cedar representation of a PolicySet. The policy names are stripped, but policies
// are emitted in lexicographical order by ID.
func (p *PolicySet) MarshalCedar() []byte {
	ids := make([]PolicyID, 0, len(p.policies))
	for k := range p.policies {
		ids = append(ids, k)
	}
	slices.Sort(ids)

	var buf bytes.Buffer
	i := 0
	for _, id := range ids {
		policy := p.policies[id]
		buf.Write(policy.MarshalCedar())

		if i < len(p.policies)-1 {
			buf.WriteString("\n\n")
		}
		i++
	}
	return buf.Bytes()
}

// MarshalJSON encodes a PolicySet in the JSON format specified by the [Cedar documentation].
//
// [Cedar documentation]: https://docs.cedarpolicy.com/policies/json-format.html
func (p *PolicySet) MarshalJSON() ([]byte, error) {
	jsonPolicySet := internaljson.PolicySetJSON{
		StaticPolicies: make(internaljson.PolicySet, len(p.policies)),
	}
	for k, v := range p.policies {
		jsonPolicySet.StaticPolicies[string(k)] = (*internaljson.Policy)(v.ast)
	}
	return json.Marshal(jsonPolicySet)
}

// UnmarshalJSON parses and compiles a PolicySet in the JSON format specified by the [Cedar documentation].
//
// [Cedar documentation]: https://docs.cedarpolicy.com/policies/json-format.html
func (p *PolicySet) UnmarshalJSON(b []byte) error {
	var jsonPolicySet internaljson.PolicySetJSON
	if err := json.Unmarshal(b, &jsonPolicySet); err != nil {
		return err
	}
	*p = PolicySet{
		policies:   make(PolicyMap, len(jsonPolicySet.StaticPolicies)),
		indexDirty: true,
	}
	for k, v := range jsonPolicySet.StaticPolicies {
		p.policies[PolicyID(k)] = newPolicy((*internalast.Policy)(v))
	}
	return nil
}

// IsAuthorized uses the combination of the PolicySet and Entities to determine
// if the given Request to determine Decision and Diagnostic.
//
// Deprecated: Use the Authorize() function instead
func (p *PolicySet) IsAuthorized(entities types.EntityGetter, req Request) (Decision, Diagnostic) {
	return Authorize(p, entities, req)
}

// All returns an iterator over the (PolicyID, *Policy) tuples in the PolicySet
func (p *PolicySet) All() iter.Seq2[PolicyID, *Policy] {
	return func(yield func(PolicyID, *Policy) bool) {
		for k, v := range p.policies {
			if !yield(k, v) {
				break
			}
		}
	}
}

// policyIndex provides fast policy lookup by action, principal type, and resource type.
type policyIndex struct {
	// Index by action EntityUID
	actionIndex map[string]map[PolicyID]struct{}
	// Index by principal entity type
	principalTypeIndex map[string]map[PolicyID]struct{}
	// Index by resource entity type
	resourceTypeIndex map[string]map[PolicyID]struct{}
	// Policies with wildcard scopes
	actionWildcards        map[PolicyID]struct{}
	principalTypeWildcards map[PolicyID]struct{}
	resourceTypeWildcards  map[PolicyID]struct{}
}

// BuildIndex pre-builds the policy index. This is optional - the index is
// automatically built on first authorization. Call this after adding all
// policies if you want to amortize the index build cost.
func (p *PolicySet) BuildIndex() {
	p.ensureIndex()
}

// ensureIndex builds or rebuilds the policy index if needed
func (p *PolicySet) ensureIndex() {
	if !p.indexDirty && p.index != nil {
		return
	}

	idx := &policyIndex{
		actionIndex:            make(map[string]map[PolicyID]struct{}),
		principalTypeIndex:     make(map[string]map[PolicyID]struct{}),
		resourceTypeIndex:      make(map[string]map[PolicyID]struct{}),
		actionWildcards:        make(map[PolicyID]struct{}),
		principalTypeWildcards: make(map[PolicyID]struct{}),
		resourceTypeWildcards:  make(map[PolicyID]struct{}),
	}

	for id, policy := range p.policies {
		ast := policy.ast
		indexAction(idx, id, ast.Action)
		indexPrincipal(idx, id, ast.Principal)
		indexResource(idx, id, ast.Resource)
	}

	p.index = idx
	p.indexDirty = false
}

// candidateSource represents a source of policy candidates for request matching.
type candidateSource struct {
	indexed   map[PolicyID]struct{}
	wildcards map[PolicyID]struct{}
	size      int
}

// makeCheckFunc creates a function that checks if a policy ID matches this source.
func (cs *candidateSource) makeCheckFunc() func(PolicyID) bool {
	indexed := cs.indexed
	wildcards := cs.wildcards
	return func(id PolicyID) bool {
		if _, ok := wildcards[id]; ok {
			return true
		}
		if indexed != nil {
			if _, ok := indexed[id]; ok {
				return true
			}
		}
		return false
	}
}

// findSmallestSource returns the index of the smallest candidate source.
func findSmallestSource(sources []candidateSource) int {
	smallest := 0
	for i := 1; i < len(sources); i++ {
		if sources[i].size < sources[smallest].size {
			smallest = i
		}
	}
	return smallest
}

// buildCheckFuncs builds check functions for all sources except the smallest.
func buildCheckFuncs(sources []candidateSource, smallest int) []func(PolicyID) bool {
	checks := make([]func(PolicyID) bool, 0, 2)
	for i := range sources {
		if i == smallest {
			continue
		}
		checks = append(checks, sources[i].makeCheckFunc())
	}
	return checks
}

// forRequest returns an iterator over policies that could match the request
func (p *PolicySet) forRequest(req Request) iter.Seq2[PolicyID, *Policy] {
	p.ensureIndex()
	idx := p.index

	// Get indexed sets
	sources := []candidateSource{
		{idx.actionIndex[req.Action.String()], idx.actionWildcards, 0},
		{idx.principalTypeIndex[string(req.Principal.Type)], idx.principalTypeWildcards, 0},
		{idx.resourceTypeIndex[string(req.Resource.Type)], idx.resourceTypeWildcards, 0},
	}
	for i := range sources {
		sources[i].size = len(sources[i].indexed) + len(sources[i].wildcards)
	}

	smallest := findSmallestSource(sources)
	checks := buildCheckFuncs(sources, smallest)
	smallestSource := sources[smallest]

	return p.iterateCandidates(smallestSource, checks)
}

// policyProcessor handles the iteration state for processing policy candidates.
type policyProcessor struct {
	policies map[PolicyID]*Policy
	checks   []func(PolicyID) bool
	yielded  map[PolicyID]struct{}
	yield    func(PolicyID, *Policy) bool
}

// process attempts to yield a policy if it passes all checks.
// Returns false if iteration should stop.
func (pp *policyProcessor) process(id PolicyID) bool {
	if _, seen := pp.yielded[id]; seen {
		return true
	}
	if !pp.passesAllChecks(id) {
		return true
	}
	policy := pp.policies[id]
	if policy == nil {
		return true
	}
	pp.yielded[id] = struct{}{}
	return pp.yield(id, policy)
}

// passesAllChecks returns true if the policy ID passes all check functions.
func (pp *policyProcessor) passesAllChecks(id PolicyID) bool {
	for _, check := range pp.checks {
		if !check(id) {
			return false
		}
	}
	return true
}

// iterateCandidates returns an iterator that yields matching policies.
func (p *PolicySet) iterateCandidates(source candidateSource, checks []func(PolicyID) bool) iter.Seq2[PolicyID, *Policy] {
	return func(yield func(PolicyID, *Policy) bool) {
		pp := &policyProcessor{
			policies: p.policies,
			checks:   checks,
			yielded:  make(map[PolicyID]struct{}),
			yield:    yield,
		}

		if !iterateSet(source.indexed, pp.process) {
			return
		}
		iterateSet(source.wildcards, pp.process)
	}
}

// iterateSet iterates over a set of policy IDs, calling process for each.
// Returns false if iteration was stopped early.
func iterateSet(set map[PolicyID]struct{}, process func(PolicyID) bool) bool {
	if set == nil {
		return true
	}
	for id := range set {
		if !process(id) {
			return false
		}
	}
	return true
}

func indexAction(idx *policyIndex, id PolicyID, scope internalast.IsActionScopeNode) {
	switch s := scope.(type) {
	case internalast.ScopeTypeAll:
		idx.actionWildcards[id] = struct{}{}
	case internalast.ScopeTypeEq:
		key := s.Entity.String()
		if idx.actionIndex[key] == nil {
			idx.actionIndex[key] = make(map[PolicyID]struct{})
		}
		idx.actionIndex[key][id] = struct{}{}
	case internalast.ScopeTypeIn:
		idx.actionWildcards[id] = struct{}{}
	case internalast.ScopeTypeInSet:
		for _, entity := range s.Entities {
			key := entity.String()
			if idx.actionIndex[key] == nil {
				idx.actionIndex[key] = make(map[PolicyID]struct{})
			}
			idx.actionIndex[key][id] = struct{}{}
		}
	default:
		idx.actionWildcards[id] = struct{}{}
	}
}

func indexPrincipal(idx *policyIndex, id PolicyID, scope internalast.IsPrincipalScopeNode) {
	switch s := scope.(type) {
	case internalast.ScopeTypeAll:
		idx.principalTypeWildcards[id] = struct{}{}
	case internalast.ScopeTypeEq:
		key := string(s.Entity.Type)
		if idx.principalTypeIndex[key] == nil {
			idx.principalTypeIndex[key] = make(map[PolicyID]struct{})
		}
		idx.principalTypeIndex[key][id] = struct{}{}
	case internalast.ScopeTypeIn:
		idx.principalTypeWildcards[id] = struct{}{}
	case internalast.ScopeTypeIs:
		key := string(s.Type)
		if idx.principalTypeIndex[key] == nil {
			idx.principalTypeIndex[key] = make(map[PolicyID]struct{})
		}
		idx.principalTypeIndex[key][id] = struct{}{}
	case internalast.ScopeTypeIsIn:
		key := string(s.Type)
		if idx.principalTypeIndex[key] == nil {
			idx.principalTypeIndex[key] = make(map[PolicyID]struct{})
		}
		idx.principalTypeIndex[key][id] = struct{}{}
	default:
		idx.principalTypeWildcards[id] = struct{}{}
	}
}

func indexResource(idx *policyIndex, id PolicyID, scope internalast.IsResourceScopeNode) {
	switch s := scope.(type) {
	case internalast.ScopeTypeAll:
		idx.resourceTypeWildcards[id] = struct{}{}
	case internalast.ScopeTypeEq:
		key := string(s.Entity.Type)
		if idx.resourceTypeIndex[key] == nil {
			idx.resourceTypeIndex[key] = make(map[PolicyID]struct{})
		}
		idx.resourceTypeIndex[key][id] = struct{}{}
	case internalast.ScopeTypeIn:
		idx.resourceTypeWildcards[id] = struct{}{}
	case internalast.ScopeTypeIs:
		key := string(s.Type)
		if idx.resourceTypeIndex[key] == nil {
			idx.resourceTypeIndex[key] = make(map[PolicyID]struct{})
		}
		idx.resourceTypeIndex[key][id] = struct{}{}
	case internalast.ScopeTypeIsIn:
		key := string(s.Type)
		if idx.resourceTypeIndex[key] == nil {
			idx.resourceTypeIndex[key] = make(map[PolicyID]struct{})
		}
		idx.resourceTypeIndex[key][id] = struct{}{}
	default:
		idx.resourceTypeWildcards[id] = struct{}{}
	}
}
