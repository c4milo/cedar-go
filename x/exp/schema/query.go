package schema

import (
	"fmt"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// ActionQueryRequest is a partial request without a concrete action.
// "What can this principal do to this resource?"
type ActionQueryRequest struct {
	Principal types.EntityUID
	Resource  types.EntityUID
	Context   types.Record
}

// PrincipalQueryRequest is a partial request without a concrete principal.
// "Which principals of this type can perform this action on this resource?"
type PrincipalQueryRequest struct {
	PrincipalType types.EntityType
	Action        types.EntityUID
	Resource      types.EntityUID
	Context       types.Record
}

// ResourceQueryRequest is a partial request without a concrete resource.
// "What resources of this type can this principal perform this action on?"
type ResourceQueryRequest struct {
	Principal    types.EntityUID
	Action       types.EntityUID
	ResourceType types.EntityType
	Context      types.Record
}

// QueryResult pairs an entity with its authorization decision.
type QueryResult struct {
	Entity              types.EntityUID
	Decision            types.Decision
	DeterminingPolicies []cedar.PolicyID
}

// DiffResult describes what changes when a policy is added or removed.
type DiffResult struct {
	// Actions that become allowed (were denied, now allowed)
	Gained []QueryResult
	// Actions that become denied (were allowed, now denied)
	Lost []QueryResult
	// Actions whose decision didn't change
	Unchanged []QueryResult
}

// QueryAction evaluates "What can this principal do to this resource?"
// For each action applicable to the principal/resource types (per schema),
// it runs authorization and returns the result.
//
// O(A) in the number of applicable actions, each requiring one Authorize call.
func (s *Schema) QueryAction(
	policies cedar.PolicyIterator,
	entities types.EntityGetter,
	req ActionQueryRequest,
) ([]QueryResult, error) {
	principalType := req.Principal.Type
	resourceType := req.Resource.Type

	actions := s.prIndex[principalResourceKey{PrincipalType: principalType, ResourceType: resourceType}]
	if len(actions) == 0 {
		return nil, nil
	}

	results := make([]QueryResult, 0, len(actions))
	for _, action := range actions {
		decision, diag := cedar.Authorize(policies, entities, types.Request{
			Principal: req.Principal,
			Action:    action,
			Resource:  req.Resource,
			Context:   req.Context,
		})

		if len(diag.Errors) > 0 {
			return results, fmt.Errorf("authorization error for action %s: %s",
				action, diag.Errors[0].Message)
		}

		result := QueryResult{
			Entity:   action,
			Decision: decision,
		}
		for _, reason := range diag.Reasons {
			result.DeterminingPolicies = append(result.DeterminingPolicies, reason.PolicyID)
		}
		results = append(results, result)
	}

	return results, nil
}

// QueryPrincipal evaluates "Which principals of this type can perform this action on this resource?"
// Iterates entities matching PrincipalType, evaluates each, returns results.
//
// O(E) in the number of entities of the given type, each requiring one Authorize call.
func (s *Schema) QueryPrincipal(
	policies cedar.PolicyIterator,
	entities types.EntityMap,
	req PrincipalQueryRequest,
) ([]QueryResult, error) {
	// Validate the action applies to this principal/resource type
	info, ok := s.actionTypes[req.Action]
	if !ok {
		return nil, fmt.Errorf("action %s not found in schema", req.Action)
	}
	if !containsType(info.PrincipalTypes, req.PrincipalType) {
		return nil, fmt.Errorf("action %s does not apply to principal type %s",
			req.Action, req.PrincipalType)
	}
	resourceType := req.Resource.Type
	if !containsType(info.ResourceTypes, resourceType) {
		return nil, fmt.Errorf("action %s does not apply to resource type %s",
			req.Action, resourceType)
	}

	var results []QueryResult
	for uid, _ := range entities {
		if uid.Type != req.PrincipalType {
			continue
		}

		decision, diag := cedar.Authorize(policies, entities, types.Request{
			Principal: uid,
			Action:    req.Action,
			Resource:  req.Resource,
			Context:   req.Context,
		})

		if len(diag.Errors) > 0 {
			return results, fmt.Errorf("authorization error for principal %s: %s",
				uid, diag.Errors[0].Message)
		}

		result := QueryResult{
			Entity:   uid,
			Decision: decision,
		}
		for _, reason := range diag.Reasons {
			result.DeterminingPolicies = append(result.DeterminingPolicies, reason.PolicyID)
		}
		results = append(results, result)
	}

	return results, nil
}

// QueryResource evaluates "What resources of this type can this principal perform this action on?"
// Iterates entities matching ResourceType, evaluates each, returns results.
//
// O(E) in the number of entities of the given type, each requiring one Authorize call.
func (s *Schema) QueryResource(
	policies cedar.PolicyIterator,
	entities types.EntityMap,
	req ResourceQueryRequest,
) ([]QueryResult, error) {
	// Validate the action applies to this principal/resource type
	info, ok := s.actionTypes[req.Action]
	if !ok {
		return nil, fmt.Errorf("action %s not found in schema", req.Action)
	}
	principalType := req.Principal.Type
	if !containsType(info.PrincipalTypes, principalType) {
		return nil, fmt.Errorf("action %s does not apply to principal type %s",
			req.Action, principalType)
	}
	if !containsType(info.ResourceTypes, req.ResourceType) {
		return nil, fmt.Errorf("action %s does not apply to resource type %s",
			req.Action, req.ResourceType)
	}

	var results []QueryResult
	for uid, _ := range entities {
		if uid.Type != req.ResourceType {
			continue
		}

		decision, diag := cedar.Authorize(policies, entities, types.Request{
			Principal: req.Principal,
			Action:    req.Action,
			Resource:  uid,
			Context:   req.Context,
		})

		if len(diag.Errors) > 0 {
			return results, fmt.Errorf("authorization error for resource %s: %s",
				uid, diag.Errors[0].Message)
		}

		result := QueryResult{
			Entity:   uid,
			Decision: decision,
		}
		for _, reason := range diag.Reasons {
			result.DeterminingPolicies = append(result.DeterminingPolicies, reason.PolicyID)
		}
		results = append(results, result)
	}

	return results, nil
}

// QueryActionDiff evaluates the permission delta when adding a policy.
// Runs QueryAction with and without the additional policy and diffs the results.
//
// O(A) in the number of applicable actions, requiring two Authorize calls each.
func (s *Schema) QueryActionDiff(
	basePolicies cedar.PolicyIterator,
	additionalPolicy *cedar.Policy,
	entities types.EntityGetter,
	req ActionQueryRequest,
) (*DiffResult, error) {
	// Get baseline results
	baseResults, err := s.QueryAction(basePolicies, entities, req)
	if err != nil {
		return nil, fmt.Errorf("baseline query failed: %w", err)
	}

	// Build merged policy set
	merged := cedar.NewPolicySet()
	for id, p := range basePolicies.All() {
		merged.Add(id, p)
	}
	merged.Add("__additional__", additionalPolicy)

	// Get results with the additional policy
	newResults, err := s.QueryAction(merged, entities, req)
	if err != nil {
		return nil, fmt.Errorf("augmented query failed: %w", err)
	}

	return diffResults(baseResults, newResults), nil
}

func diffResults(base, updated []QueryResult) *DiffResult {
	diff := &DiffResult{}

	baseMap := make(map[types.EntityUID]types.Decision, len(base))
	for _, r := range base {
		baseMap[r.Entity] = r.Decision
	}

	for _, r := range updated {
		baseDec, existed := baseMap[r.Entity]
		switch {
		case !existed:
			// New action not in base — treat as gained if allowed
			if r.Decision == types.Allow {
				diff.Gained = append(diff.Gained, r)
			} else {
				diff.Unchanged = append(diff.Unchanged, r)
			}
		case baseDec == types.Deny && r.Decision == types.Allow:
			diff.Gained = append(diff.Gained, r)
		case baseDec == types.Allow && r.Decision == types.Deny:
			diff.Lost = append(diff.Lost, r)
		default:
			diff.Unchanged = append(diff.Unchanged, r)
		}
	}

	return diff
}

func containsType(list []types.EntityType, t types.EntityType) bool {
	for _, et := range list {
		if et == t {
			return true
		}
	}
	return false
}
