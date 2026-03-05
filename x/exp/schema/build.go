package schema

import (
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/schema/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema/resolved"
)

// buildFromResolved populates the precomputed maps and indexes from a
// resolved.Schema. Called once during construction; the Schema is
// immutable afterwards.
func (s *Schema) buildFromResolved(rs *resolved.Schema) {
	s.entityTypes = make(map[types.EntityType]*EntityTypeInfo, len(rs.Entities)+len(rs.Enums))
	s.actionTypes = make(map[types.EntityUID]*ActionTypeInfo, len(rs.Actions))
	s.commonTypes = make(map[string]CedarType)

	// Entity types
	for name, ent := range rs.Entities {
		info := &EntityTypeInfo{
			Attributes:    convertRecordAttrs(ent.Shape),
			MemberOfTypes: ent.ParentTypes,
			Annotations:   convertAnnotations(ent.Annotations),
		}
		if ent.Shape == nil {
			info.OpenRecord = true
		}
		s.entityTypes[name] = info
	}

	// Enum types are presented as entity types with no attributes.
	for name, enum := range rs.Enums {
		s.entityTypes[name] = &EntityTypeInfo{
			Attributes:  map[string]AttributeType{},
			Annotations: convertAnnotations(enum.Annotations),
		}
	}

	// Actions
	for uid, act := range rs.Actions {
		info := &ActionTypeInfo{
			Annotations: convertAnnotations(act.Annotations),
		}
		if act.AppliesTo != nil {
			info.PrincipalTypes = act.AppliesTo.Principals
			info.ResourceTypes = act.AppliesTo.Resources
			info.Context = convertRecordType(act.AppliesTo.Context)
		}
		// Collect memberOf from entity parents.
		for parent := range act.Entity.Parents.All() {
			info.MemberOf = append(info.MemberOf, parent)
		}
		s.actionTypes[uid] = info
	}

	// Common types: populate from the AST. The resolver inlines common types,
	// so they don't appear in the resolved schema. We walk the AST to expose
	// them for introspection and validator use.
	s.buildCommonTypes()

	s.buildDerivedData()
}

// buildDerivedData precomputes all derived indexes from the type maps.
func (s *Schema) buildDerivedData() {
	seenPrincipals := make(map[types.EntityType]struct{})
	seenResources := make(map[types.EntityType]struct{})
	s.prIndex = make(map[principalResourceKey][]types.EntityUID)
	s.actionEntities = make(types.EntityMap)

	for uid, info := range s.actionTypes {
		isLeaf := len(info.PrincipalTypes) > 0 || len(info.ResourceTypes) > 0
		if isLeaf {
			s.leafActions = append(s.leafActions, uid)
		} else {
			s.groupActions = append(s.groupActions, uid)
		}

		for _, pt := range info.PrincipalTypes {
			if _, exists := seenPrincipals[pt]; !exists {
				seenPrincipals[pt] = struct{}{}
				s.principals = append(s.principals, pt)
			}
		}
		for _, rt := range info.ResourceTypes {
			if _, exists := seenResources[rt]; !exists {
				seenResources[rt] = struct{}{}
				s.resources = append(s.resources, rt)
			}
		}

		for _, pt := range info.PrincipalTypes {
			for _, rt := range info.ResourceTypes {
				key := principalResourceKey{PrincipalType: pt, ResourceType: rt}
				s.prIndex[key] = append(s.prIndex[key], uid)
				s.requestEnvs = append(s.requestEnvs, RequestEnv{
					PrincipalType: pt,
					Action:        uid,
					ResourceType:  rt,
				})
			}
		}

		parents := make([]types.EntityUID, len(info.MemberOf))
		copy(parents, info.MemberOf)
		s.actionEntities[uid] = types.Entity{
			UID:        uid,
			Parents:    types.NewEntityUIDSet(parents...),
			Attributes: types.NewRecord(nil),
		}
	}
}

// buildCommonTypes populates the commonTypes map from the AST.
// The resolved schema inlines common types, so we walk the AST to get names.
func (s *Schema) buildCommonTypes() {
	if s.inner == nil {
		return
	}
	collectCommonTypes(s.commonTypes, "", s.inner.CommonTypes)
	for nsName, ns := range s.inner.Namespaces {
		collectCommonTypes(s.commonTypes, string(nsName), ns.CommonTypes)
	}
}

func collectCommonTypes(dst map[string]CedarType, ns string, cts ast.CommonTypes) {
	for name, ct := range cts {
		fqn := qualifyName(ns, string(name))
		dst[fqn] = convertASTType(ct.Type)
	}
}

// convertASTType converts an ast.IsType to our CedarType interface.
func convertASTType(t ast.IsType) CedarType {
	if t == nil {
		return UnknownType{}
	}
	switch t := t.(type) {
	case ast.StringType:
		return StringType{}
	case ast.LongType:
		return LongType{}
	case ast.BoolType:
		return BoolType{}
	case ast.ExtensionType:
		return ExtensionType{Name: string(t)}
	case ast.SetType:
		return SetType{Element: convertASTType(t.Element)}
	case ast.RecordType:
		return convertASTRecordType(t)
	case ast.EntityTypeRef:
		return EntityCedarType{Name: types.EntityType(t)}
	case ast.TypeRef:
		// Unresolved reference — treat as an unknown type at this level.
		// The actual type is already inlined in entity/action shapes.
		return UnknownType{}
	default:
		return UnknownType{}
	}
}

func convertASTRecordType(rec ast.RecordType) RecordType {
	attrs := make(map[string]AttributeType, len(rec))
	for name, attr := range rec {
		attrs[string(name)] = AttributeType{
			Type:     convertASTType(attr.Type),
			Required: !attr.Optional,
		}
	}
	return RecordType{Attributes: attrs}
}

// convertType converts a resolved.IsType to our CedarType interface.
func convertType(t resolved.IsType) CedarType {
	if t == nil {
		return UnknownType{}
	}
	switch t := t.(type) {
	case resolved.StringType:
		return StringType{}
	case resolved.LongType:
		return LongType{}
	case resolved.BoolType:
		return BoolType{}
	case resolved.ExtensionType:
		return ExtensionType{Name: string(t)}
	case resolved.SetType:
		return SetType{Element: convertType(t.Element)}
	case resolved.RecordType:
		return convertRecordType(t)
	case resolved.EntityType:
		return EntityCedarType{Name: types.EntityType(t)}
	default:
		return UnknownType{}
	}
}

// convertRecordType converts a resolved.RecordType to our RecordType.
func convertRecordType(rec resolved.RecordType) RecordType {
	attrs := make(map[string]AttributeType, len(rec))
	for name, attr := range rec {
		attrs[string(name)] = AttributeType{
			Type:     convertType(attr.Type),
			Required: !attr.Optional,
		}
	}
	return RecordType{Attributes: attrs}
}

// convertRecordAttrs converts a resolved.RecordType to map[string]AttributeType.
func convertRecordAttrs(rec resolved.RecordType) map[string]AttributeType {
	attrs := make(map[string]AttributeType, len(rec))
	for name, attr := range rec {
		attrs[string(name)] = AttributeType{
			Type:     convertType(attr.Type),
			Required: !attr.Optional,
		}
	}
	return attrs
}

// convertAnnotations converts resolved.Annotations to the public Annotations type.
func convertAnnotations(ra resolved.Annotations) Annotations {
	if len(ra) == 0 {
		return nil
	}
	a := make(Annotations, len(ra))
	for k, v := range ra {
		a[string(k)] = string(v)
	}
	return a
}
