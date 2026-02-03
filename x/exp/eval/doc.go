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

// Package eval provides advanced evaluation APIs for Cedar policies, including
// partial evaluation, residual policy analysis, entity loading, and query APIs.
//
// # Query APIs
//
// The Query APIs allow you to determine which principals, resources, or actions
// would satisfy a set of policies. This is useful for building UIs that show
// available permissions, or for analyzing what access a user has.
//
// # QueryActions
//
// QueryActions finds which actions a given principal can perform on a given resource.
// This is particularly useful for UI permission checking - showing or hiding buttons
// based on what actions the current user can perform.
//
// Example: Determine which actions a user can perform on a document
//
//	// Build your policy set
//	policies := map[types.PolicyID]*ast.Policy{
//	    "viewer": ast.Permit().
//	        PrincipalIn(types.NewEntityUID("Group", "viewers")).
//	        ActionInSet(
//	            types.NewEntityUID("Action", "view"),
//	            types.NewEntityUID("Action", "download"),
//	        ),
//	    "editor": ast.Permit().
//	        PrincipalIn(types.NewEntityUID("Group", "editors")).
//	        ActionInSet(
//	            types.NewEntityUID("Action", "view"),
//	            types.NewEntityUID("Action", "edit"),
//	            types.NewEntityUID("Action", "delete"),
//	        ),
//	}
//
//	// Query which actions alice can perform on report.pdf
//	result := eval.QueryActions(
//	    policies,
//	    entities,
//	    types.NewEntityUID("User", "alice"),
//	    types.NewEntityUID("Document", "report.pdf"),
//	    types.Record{},
//	)
//
//	// Use the result to show/hide UI buttons
//	if result.All {
//	    // User can perform any action
//	} else {
//	    for _, action := range result.SatisfyingValues {
//	        switch action.ID {
//	        case "view":
//	            showViewButton()
//	        case "edit":
//	            showEditButton()
//	        case "delete":
//	            showDeleteButton()
//	        }
//	    }
//	}
//
// # QueryPrincipals
//
// QueryPrincipals finds which principals would be permitted to perform an action
// on a resource. This is useful for answering questions like "who can access this
// document?" or building access control lists.
//
// Example: Find who can read a document
//
//	result := eval.QueryPrincipals(
//	    policies,
//	    entities,
//	    types.NewEntityUID("Action", "read"),
//	    types.NewEntityUID("Document", "confidential.pdf"),
//	    types.Record{},
//	)
//
//	if result.All {
//	    fmt.Println("Anyone can read this document")
//	} else if len(result.SatisfyingValues) > 0 {
//	    fmt.Println("These users can read:")
//	    for _, principal := range result.SatisfyingValues {
//	        fmt.Printf("  - %s\n", principal)
//	    }
//	} else {
//	    fmt.Println("No one can read this document")
//	}
//
// # QueryResources
//
// QueryResources finds which resources a principal can access with a given action.
// This is useful for building resource browsers or listing accessible items.
//
// Example: Find what documents a user can view
//
//	result := eval.QueryResources(
//	    policies,
//	    entities,
//	    types.NewEntityUID("User", "alice"),
//	    types.NewEntityUID("Action", "view"),
//	    types.Record{},
//	)
//
//	for _, resource := range result.SatisfyingValues {
//	    fmt.Printf("Alice can view: %s\n", resource)
//	}
//
// # QueryDecision
//
// QueryDecision provides detailed information about an authorization decision,
// including which policies contributed to the outcome.
//
//	result := eval.QueryDecision(
//	    policies,
//	    entities,
//	    types.NewEntityUID("User", "alice"),
//	    types.NewEntityUID("Action", "delete"),
//	    types.NewEntityUID("Document", "report.pdf"),
//	    types.Record{},
//	)
//
//	if result.Decision == types.Allow {
//	    fmt.Printf("Allowed by policies: %v\n", result.DeterminingPolicies)
//	} else {
//	    fmt.Printf("Denied. Determining policies: %v\n", result.DeterminingPolicies)
//	}
//
// # Understanding Query Results
//
// QueryResult contains several fields to help understand the query outcome:
//
//   - Decision: Whether any values satisfy the query (Allow) or not (Deny)
//   - All: True if all possible values satisfy the query
//   - SatisfyingValues: Specific EntityUIDs that satisfy the query
//   - Definite: True if the result is conclusive (no residual policies)
//   - Constraints: Residual constraints that couldn't be fully resolved
//
// When Definite is false, it means there are residual policies that depend on
// runtime information not available during the query. The Constraints field
// provides hints about what additional values might satisfy the query.
//
// # Partial Evaluation
//
// The Query APIs are built on top of partial evaluation (also known as
// Trivial Policy Evaluation or TPE). Partial evaluation allows you to
// evaluate policies with unknown values, producing "residual" policies
// that represent the remaining conditions.
//
// You can use partial evaluation directly for more advanced use cases:
//
//	env := eval.Env{
//	    Principal: types.NewEntityUID("User", "alice"),
//	    Action:    eval.Variable("action"),  // Unknown
//	    Resource:  types.NewEntityUID("Document", "report.pdf"),
//	    Context:   types.Record{},
//	    Entities:  entities,
//	}
//
//	residuals := eval.PartialPolicySet(env, policies)
//	// Analyze residuals.Permits and residuals.Forbids
//
// # Entity Loading
//
// The package also provides EntityLoader for dynamic entity loading during
// evaluation, which is useful when you don't want to load all entities upfront.
package eval
