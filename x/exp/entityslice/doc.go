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

// Package entityslice provides entity slicing capabilities for Cedar authorization.
//
// Entity slicing computes the minimal set of entities needed to evaluate
// authorization requests, reducing data transfer and improving performance.
// This is particularly useful when you have a large entity store but policies
// only access a subset of entity data.
//
// # Overview
//
// The package works in two phases:
//
//  1. Manifest Computation: Analyze policies to determine what entity data
//     (attributes, ancestors) may be accessed during authorization.
//
//  2. Entity Slicing: For a specific request, extract only the entities and
//     attributes that are actually needed.
//
// # Usage
//
//	// Compute a manifest from policies and schema
//	manifest, err := entityslice.ComputeManifest(validator, policies)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Slice entities for a specific request
//	slice := manifest.SliceEntities(allEntities, request)
//
//	// Authorize with the smaller slice (same result, less data)
//	decision, _ := cedar.Authorize(policies, slice, request)
//
// # Benefits
//
//   - Reduced memory usage: Only load entities that matter
//   - Faster network transfer: Send less data between services
//   - Improved cache efficiency: Cache smaller, more targeted entity sets
//
// # Experimental
//
// This package is experimental and may change in future versions.
package entityslice
