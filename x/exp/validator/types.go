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

package validator

import "github.com/cedar-policy/cedar-go/x/exp/schema"

// All type definitions are aliases to the canonical types in the schema package.
// This preserves backward compatibility for any code that references these types
// from the validator package.

type CedarType = schema.CedarType

type BoolType = schema.BoolType
type LongType = schema.LongType
type StringType = schema.StringType
type EntityType = schema.EntityCedarType
type SetType = schema.SetType
type RecordType = schema.RecordType
type AttributeType = schema.AttributeType
type ExtensionType = schema.ExtensionType
type AnyEntityType = schema.AnyEntityType
type UnknownType = schema.UnknownType
type UnspecifiedType = schema.UnspecifiedType
type EntityTypeInfo = schema.EntityTypeInfo
type ActionTypeInfo = schema.ActionTypeInfo

var TypesMatch = schema.TypesMatch
