package entityslice

import (
	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/validator"
)

// EntityManifest describes what entity data is needed for authorization.
// It is computed from a policy set and schema, and can be used to slice
// entities for specific requests.
type EntityManifest struct {
	// MaxLevel is the maximum depth of entity attribute access in policies.
	// Level 0 means no attribute access, level 1 means direct attributes,
	// level 2 means one level of chaining (e.g., principal.manager.dept), etc.
	MaxLevel int

	// RequiredAttributes maps entity types to the attributes that may be accessed.
	// If nil, all attributes should be included.
	RequiredAttributes map[types.EntityType]map[types.Ident]bool

	// RequiredAncestorTypes maps entity types to the ancestor types that may be
	// checked via the `in` operator.
	RequiredAncestorTypes map[types.EntityType]map[types.EntityType]bool

	// EntityLiterals contains entity UIDs that are explicitly referenced in policies.
	EntityLiterals map[types.EntityUID]bool
}

// ComputeManifest analyzes policies against a schema to determine what entity
// data may be accessed during authorization.
//
// The manifest can then be used to slice entities for specific requests,
// reducing the amount of data needed for authorization.
func ComputeManifest(v *validator.Validator, policies *cedar.PolicySet) (*EntityManifest, error) {
	manifest := &EntityManifest{
		MaxLevel:              0,
		RequiredAttributes:    make(map[types.EntityType]map[types.Ident]bool),
		RequiredAncestorTypes: make(map[types.EntityType]map[types.EntityType]bool),
		EntityLiterals:        make(map[types.EntityUID]bool),
	}

	// Analyze each policy
	for _, policy := range policies.All() {
		policyAST := (*ast.Policy)(policy.AST())
		analyzePolicy(manifest, policyAST)
	}

	return manifest, nil
}

// ComputeManifestFromSchema is a convenience function that creates a validator
// and computes the manifest.
func ComputeManifestFromSchema(s *schema.Schema, policies *cedar.PolicySet) (*EntityManifest, error) {
	v, err := validator.New(s)
	if err != nil {
		return nil, err
	}
	return ComputeManifest(v, policies)
}

// analyzePolicy extracts entity access patterns from a single policy.
func analyzePolicy(manifest *EntityManifest, policy *ast.Policy) {
	// Analyze scope constraints for entity literals
	analyzeScopeNode(manifest, policy.Principal)
	analyzeScopeNode(manifest, policy.Action)
	analyzeScopeNode(manifest, policy.Resource)

	// Analyze conditions
	for _, cond := range policy.Conditions {
		analyzeNode(manifest, cond.Body, 0)
	}
}

// analyzeScopeNode extracts entity literals from scope nodes.
func analyzeScopeNode(manifest *EntityManifest, node any) {
	switch n := node.(type) {
	case ast.ScopeTypeEq:
		manifest.EntityLiterals[n.Entity] = true
	case ast.ScopeTypeIn:
		manifest.EntityLiterals[n.Entity] = true
	case ast.ScopeTypeInSet:
		for _, e := range n.Entities {
			manifest.EntityLiterals[e] = true
		}
	case ast.ScopeTypeIsIn:
		manifest.EntityLiterals[n.Entity] = true
	}
}

// analyzeNode recursively analyzes an AST node for entity access patterns.
func analyzeNode(manifest *EntityManifest, node ast.IsNode, depth int) {
	if node == nil {
		return
	}

	if depth > manifest.MaxLevel {
		manifest.MaxLevel = depth
	}

	switch n := node.(type) {
	case ast.NodeTypeAccess:
		analyzeNode(manifest, n.Arg, depth+1)
	case ast.NodeTypeGetTag:
		analyzeGetTagNode(manifest, n, depth)
	case ast.NodeValue:
		analyzeValueNode(manifest, n)
	case ast.NodeTypeVariable:
		// Terminal - no children to analyze
	default:
		analyzeNodeChildren(manifest, node, depth)
	}
}

// analyzeGetTagNode handles tag node analysis with depth tracking.
func analyzeGetTagNode(manifest *EntityManifest, n ast.NodeTypeGetTag, depth int) {
	analyzeNode(manifest, n.Left, depth+1)
	analyzeNode(manifest, n.Right, depth)
}

// analyzeValueNode handles value node analysis for entity literals.
func analyzeValueNode(manifest *EntityManifest, n ast.NodeValue) {
	if uid, ok := n.Value.(types.EntityUID); ok {
		manifest.EntityLiterals[uid] = true
	}
}

// analyzeNodeChildren handles standard node children at the same depth.
func analyzeNodeChildren(manifest *EntityManifest, node ast.IsNode, depth int) {
	for _, child := range getManifestNodeChildren(node) {
		analyzeNode(manifest, child, depth)
	}
}

// getManifestNodeChildren returns the child nodes of an AST node for manifest analysis.
func getManifestNodeChildren(n ast.IsNode) []ast.IsNode {
	switch v := n.(type) {
	// Unary nodes
	case ast.NodeTypeNot:
		return []ast.IsNode{v.Arg}
	case ast.NodeTypeNegate:
		return []ast.IsNode{v.Arg}
	case ast.NodeTypeIsEmpty:
		return []ast.IsNode{v.Arg}
	case ast.NodeTypeHas:
		return []ast.IsNode{v.Arg}
	case ast.NodeTypeLike:
		return []ast.IsNode{v.Arg}
	case ast.NodeTypeIs:
		return []ast.IsNode{v.Left}
	// Ternary node
	case ast.NodeTypeIfThenElse:
		return []ast.IsNode{v.If, v.Then, v.Else}
	// Container nodes
	case ast.NodeTypeExtensionCall:
		return v.Args
	case ast.NodeTypeSet:
		return v.Elements
	case ast.NodeTypeRecord:
		return getRecordValueChildren(v)
	// IsIn and tag nodes
	case ast.NodeTypeIsIn:
		return []ast.IsNode{v.Left, v.Entity}
	case ast.NodeTypeHasTag:
		return []ast.IsNode{v.Left, v.Right}
	// Binary nodes
	default:
		return getBinaryChildren(n)
	}
}

// getRecordValueChildren extracts value nodes from a record.
func getRecordValueChildren(r ast.NodeTypeRecord) []ast.IsNode {
	children := make([]ast.IsNode, 0, len(r.Elements))
	for _, elem := range r.Elements {
		children = append(children, elem.Value)
	}
	return children
}

// getBinaryChildren returns children for binary operator nodes.
func getBinaryChildren(n ast.IsNode) []ast.IsNode {
	switch v := n.(type) {
	case ast.NodeTypeAnd:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeOr:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeIn:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeEquals:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeNotEquals:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeLessThan:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeLessThanOrEqual:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeGreaterThan:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeGreaterThanOrEqual:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeAdd:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeSub:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeMult:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeContains:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeContainsAll:
		return []ast.IsNode{v.Left, v.Right}
	case ast.NodeTypeContainsAny:
		return []ast.IsNode{v.Left, v.Right}
	}
	return nil
}

// SliceEntities returns a subset of entities relevant to the given request,
// based on the manifest's analysis of policy requirements.
func (m *EntityManifest) SliceEntities(entities types.EntityMap, req cedar.Request) types.EntityMap {
	ctx := &sliceContext{
		entities: entities,
		slice:    make(types.EntityMap),
		visited:  make(map[types.EntityUID]bool),
		maxLevel: m.MaxLevel,
	}

	workSet := m.buildInitialWorkSet(req)
	ctx.collectEntitiesBFS(workSet)

	return ctx.slice
}

// sliceContext holds state during entity slicing.
type sliceContext struct {
	entities types.EntityMap
	slice    types.EntityMap
	visited  map[types.EntityUID]bool
	maxLevel int
}

// buildInitialWorkSet creates the initial set of entities to process.
func (m *EntityManifest) buildInitialWorkSet(req cedar.Request) []types.EntityUID {
	workSet := []types.EntityUID{req.Principal, req.Action, req.Resource}
	for uid := range m.EntityLiterals {
		workSet = append(workSet, uid)
	}
	collectEntityRefsFromValue(req.Context, &workSet)
	return workSet
}

// collectEntitiesBFS collects entities using breadth-first traversal.
func (ctx *sliceContext) collectEntitiesBFS(workSet []types.EntityUID) {
	for level := 0; level <= ctx.maxLevel && len(workSet) > 0; level++ {
		workSet = ctx.processLevel(workSet, level)
	}
}

// processLevel processes all entities at the current level.
func (ctx *sliceContext) processLevel(workSet []types.EntityUID, level int) []types.EntityUID {
	var nextWork []types.EntityUID
	for _, uid := range workSet {
		ctx.processEntity(uid, level, &nextWork)
	}
	return nextWork
}

// processEntity processes a single entity, adding it to the slice and collecting related entities.
func (ctx *sliceContext) processEntity(uid types.EntityUID, level int, nextWork *[]types.EntityUID) {
	if ctx.visited[uid] {
		return
	}
	ctx.visited[uid] = true

	entity, exists := ctx.entities[uid]
	if !exists {
		return
	}

	ctx.slice[uid] = entity
	ctx.collectParents(entity, nextWork)

	if level < ctx.maxLevel {
		ctx.collectAttributeRefs(entity, nextWork)
	}
}

// collectParents adds unvisited parent entities to the work set.
func (ctx *sliceContext) collectParents(entity types.Entity, nextWork *[]types.EntityUID) {
	for parent := range entity.Parents.All() {
		if !ctx.visited[parent] {
			*nextWork = append(*nextWork, parent)
		}
	}
}

// collectAttributeRefs adds entity references from attributes to the work set.
func (ctx *sliceContext) collectAttributeRefs(entity types.Entity, nextWork *[]types.EntityUID) {
	for _, attrValue := range entity.Attributes.All() {
		collectEntityRefsFromValue(attrValue, nextWork)
	}
}

// collectEntityRefsFromValue recursively finds EntityUID values in a Cedar value.
func collectEntityRefsFromValue(v types.Value, refs *[]types.EntityUID) {
	switch val := v.(type) {
	case types.EntityUID:
		*refs = append(*refs, val)
	case types.Set:
		for elem := range val.All() {
			collectEntityRefsFromValue(elem, refs)
		}
	case types.Record:
		for _, fieldVal := range val.All() {
			collectEntityRefsFromValue(fieldVal, refs)
		}
	}
}

// SlicingEntityGetter wraps an EntityGetter to only return entities in a slice.
type SlicingEntityGetter struct {
	underlying types.EntityGetter
	allowed    map[types.EntityUID]bool
}

// NewSlicingEntityGetter creates an EntityGetter that only returns entities
// in the given slice.
func NewSlicingEntityGetter(underlying types.EntityGetter, slice types.EntityMap) *SlicingEntityGetter {
	allowed := make(map[types.EntityUID]bool, len(slice))
	for uid := range slice {
		allowed[uid] = true
	}
	return &SlicingEntityGetter{
		underlying: underlying,
		allowed:    allowed,
	}
}

// Get returns an entity only if it's in the allowed slice.
func (s *SlicingEntityGetter) Get(uid types.EntityUID) (types.Entity, bool) {
	if !s.allowed[uid] {
		return types.Entity{}, false
	}
	return s.underlying.Get(uid)
}
