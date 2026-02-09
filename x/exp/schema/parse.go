package schema

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cedar-policy/cedar-go/types"
)

// parse extracts type information from the raw JSON schema into the typed maps,
// then builds all precomputed derived data. Called during Schema construction.
func (s *Schema) parse() error {
	s.entityTypes = make(map[types.EntityType]*EntityTypeInfo)
	s.actionTypes = make(map[types.EntityUID]*ActionTypeInfo)
	s.commonTypes = make(map[string]CedarType)

	if s.jsonSchema == nil {
		s.prIndex = make(map[principalResourceKey][]types.EntityUID)
		s.actionEntities = make(types.EntityMap)
		return nil
	}

	// Get JSON representation to access schema details
	jsonBytes, err := s.MarshalJSON()
	if err != nil {
		return err
	}

	if err := s.parseSchemaJSON(jsonBytes); err != nil {
		return err
	}

	s.buildDerivedData()
	return nil
}

// buildDerivedData precomputes all derived indexes from the parsed type maps.
// Schema is immutable after construction so these never need rebuilding.
func (s *Schema) buildDerivedData() {
	seenPrincipals := make(map[types.EntityType]struct{})
	seenResources := make(map[types.EntityType]struct{})
	s.prIndex = make(map[principalResourceKey][]types.EntityUID)
	s.actionEntities = make(types.EntityMap)

	for uid, info := range s.actionTypes {
		// Classify leaf vs group
		isLeaf := len(info.PrincipalTypes) > 0 || len(info.ResourceTypes) > 0
		if isLeaf {
			s.leafActions = append(s.leafActions, uid)
		} else {
			s.groupActions = append(s.groupActions, uid)
		}

		// Collect unique principals and resources
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

		// Build (principal, resource) → actions reverse index and request envs
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

		// Build action entity for hierarchy
		parents := make([]types.EntityUID, len(info.MemberOf))
		copy(parents, info.MemberOf)
		s.actionEntities[uid] = types.Entity{
			UID:        uid,
			Parents:    types.NewEntityUIDSet(parents...),
			Attributes: types.NewRecord(nil),
		}
	}
}

// -----------------------------------------------------------------------------
// JSON Schema Types (for parsing)
// -----------------------------------------------------------------------------

type jsonNamespace struct {
	EntityTypes map[string]jsonEntityType `json:"entityTypes"`
	Actions     map[string]jsonAction     `json:"actions"`
	CommonTypes map[string]jsonType       `json:"commonTypes,omitempty"`
}

type jsonEntityType struct {
	Shape         *jsonType `json:"shape,omitempty"`
	MemberOfTypes []string  `json:"memberOfTypes,omitempty"`
}

type jsonAction struct {
	AppliesTo *jsonAppliesTo  `json:"appliesTo,omitempty"`
	MemberOf  []jsonActionRef `json:"memberOf,omitempty"`
	Context   *jsonType       `json:"context,omitempty"`
}

type jsonAppliesTo struct {
	PrincipalTypes []string  `json:"principalTypes,omitempty"`
	ResourceTypes  []string  `json:"resourceTypes,omitempty"`
	Context        *jsonType `json:"context,omitempty"`
}

type jsonActionRef struct {
	Type string `json:"type,omitempty"`
	ID   string `json:"id"`
}

type jsonType struct {
	Type       string              `json:"type"`
	Element    *jsonType           `json:"element,omitempty"`
	Attributes map[string]jsonAttr `json:"attributes,omitempty"`
	Name       string              `json:"name,omitempty"`
}

type jsonAttr struct {
	Type       string              `json:"type,omitempty"`
	Element    *jsonType           `json:"element,omitempty"`
	Required   *bool               `json:"required,omitempty"`
	Name       string              `json:"name,omitempty"`
	Attributes map[string]jsonAttr `json:"attributes,omitempty"`
}

// parseSchemaJSON parses the JSON schema into type information.
func (s *Schema) parseSchemaJSON(data []byte) error {
	var namespaces map[string]*jsonNamespace
	if err := json.Unmarshal(data, &namespaces); err != nil {
		return fmt.Errorf("failed to parse schema JSON: %w", err)
	}

	for nsName, ns := range namespaces {
		if ns == nil {
			continue
		}
		if err := s.parseNamespace(nsName, ns); err != nil {
			return err
		}
	}

	return nil
}

func (s *Schema) parseNamespace(nsName string, ns *jsonNamespace) error {
	if err := s.parseCommonTypes(nsName, ns.CommonTypes); err != nil {
		return err
	}
	if err := s.parseEntityTypes(nsName, ns.EntityTypes); err != nil {
		return err
	}
	return s.parseActions(nsName, ns.Actions)
}

func (s *Schema) parseCommonTypes(nsName string, commonTypes map[string]jsonType) error {
	for name, jt := range commonTypes {
		fullName := qualifyParseName(nsName, name)
		ct, err := s.parseJSONType(&jt)
		if err != nil {
			return fmt.Errorf("failed to parse common type %s: %w", fullName, err)
		}
		s.commonTypes[fullName] = ct
	}
	return nil
}

func (s *Schema) parseEntityTypes(nsName string, entityTypes map[string]jsonEntityType) error {
	for name, et := range entityTypes {
		fullName := qualifyParseName(nsName, name)
		info, err := s.parseEntityType(nsName, fullName, &et)
		if err != nil {
			return err
		}
		s.entityTypes[types.EntityType(fullName)] = info
	}
	return nil
}

func (s *Schema) parseEntityType(nsName, fullName string, et *jsonEntityType) (*EntityTypeInfo, error) {
	info := &EntityTypeInfo{
		Attributes:    make(map[string]AttributeType),
		MemberOfTypes: make([]types.EntityType, 0, len(et.MemberOfTypes)),
	}

	if err := s.parseEntityShape(info, fullName, et.Shape); err != nil {
		return nil, err
	}

	seen := make(map[types.EntityType]struct{})
	for _, mot := range et.MemberOfTypes {
		et := types.EntityType(qualifyParseTypeName(nsName, mot))
		if _, exists := seen[et]; !exists {
			info.MemberOfTypes = append(info.MemberOfTypes, et)
			seen[et] = struct{}{}
		}
	}

	return info, nil
}

func (s *Schema) parseEntityShape(info *EntityTypeInfo, entityName string, shape *jsonType) error {
	if shape == nil {
		info.OpenRecord = true
		return nil
	}

	if shape.Attributes != nil {
		for attrName, attr := range shape.Attributes {
			at, err := s.parseJSONAttr(&attr)
			if err != nil {
				return fmt.Errorf("failed to parse attribute %s.%s: %w", entityName, attrName, err)
			}
			info.Attributes[attrName] = at
		}
	}

	info.OpenRecord = false
	return nil
}

func (s *Schema) parseActions(nsName string, actions map[string]jsonAction) error {
	for name, act := range actions {
		info, err := s.parseAction(nsName, name, &act)
		if err != nil {
			return err
		}
		actionType := qualifyParseName(nsName, "Action")
		actionUID := types.EntityUID{Type: types.EntityType(actionType), ID: types.String(name)}
		s.actionTypes[actionUID] = info
	}
	return nil
}

func (s *Schema) parseAction(nsName, name string, act *jsonAction) (*ActionTypeInfo, error) {
	info := &ActionTypeInfo{
		PrincipalTypes: make([]types.EntityType, 0),
		ResourceTypes:  make([]types.EntityType, 0),
		Context:        RecordType{Attributes: make(map[string]AttributeType)},
		MemberOf:       make([]types.EntityUID, 0),
	}

	if err := s.parseAppliesTo(info, nsName, name, act.AppliesTo); err != nil {
		return nil, err
	}

	if act.Context != nil {
		ctx, err := s.parseRecordTypeWithOpen(act.Context)
		if err != nil {
			return nil, fmt.Errorf("failed to parse action %s context: %w", name, err)
		}
		info.Context = ctx
	}

	s.parseActionMemberOf(info, nsName, act.MemberOf)

	return info, nil
}

func (s *Schema) parseAppliesTo(info *ActionTypeInfo, nsName, actionName string, appliesTo *jsonAppliesTo) error {
	if appliesTo == nil {
		return nil
	}

	seenPrincipal := make(map[types.EntityType]struct{})
	for _, pt := range appliesTo.PrincipalTypes {
		et := types.EntityType(qualifyParseTypeName(nsName, pt))
		if _, exists := seenPrincipal[et]; !exists {
			info.PrincipalTypes = append(info.PrincipalTypes, et)
			seenPrincipal[et] = struct{}{}
		}
	}

	seenResource := make(map[types.EntityType]struct{})
	for _, rt := range appliesTo.ResourceTypes {
		et := types.EntityType(qualifyParseTypeName(nsName, rt))
		if _, exists := seenResource[et]; !exists {
			info.ResourceTypes = append(info.ResourceTypes, et)
			seenResource[et] = struct{}{}
		}
	}

	if appliesTo.Context != nil {
		ctx, err := s.parseRecordTypeWithOpen(appliesTo.Context)
		if err != nil {
			return fmt.Errorf("failed to parse action %s context: %w", actionName, err)
		}
		info.Context = ctx
	}

	return nil
}

func (s *Schema) parseActionMemberOf(info *ActionTypeInfo, nsName string, memberOf []jsonActionRef) {
	for _, mo := range memberOf {
		typ := qualifyParseName(nsName, "Action")
		if mo.Type != "" {
			typ = mo.Type
		}
		info.MemberOf = append(info.MemberOf, types.EntityUID{
			Type: types.EntityType(typ),
			ID:   types.String(mo.ID),
		})
	}
}

// -----------------------------------------------------------------------------
// Type Parsing Helpers
// -----------------------------------------------------------------------------

func qualifyParseName(namespace, localName string) string {
	if namespace == "" {
		return localName
	}
	return namespace + "::" + localName
}

func qualifyParseTypeName(namespace, typeName string) string {
	if namespace == "" || strings.Contains(typeName, "::") {
		return typeName
	}
	return namespace + "::" + typeName
}

func (s *Schema) parseJSONType(jt *jsonType) (CedarType, error) {
	if jt == nil {
		return RecordType{Attributes: make(map[string]AttributeType)}, nil
	}

	switch jt.Type {
	case "Boolean", "Bool":
		return BoolType{}, nil
	case "Long":
		return LongType{}, nil
	case "String":
		return StringType{}, nil
	case "Entity":
		return s.parseEntityRefType(jt.Name), nil
	case "Set":
		return s.parseSetType(jt.Element)
	case "Record":
		return s.parseRecordType(jt.Attributes)
	case "Extension":
		return s.parseExtensionType(jt.Name), nil
	default:
		return s.parseTypeReference(jt.Type)
	}
}

func (s *Schema) parseEntityRefType(name string) CedarType {
	if name != "" {
		return EntityCedarType{Name: types.EntityType(name)}
	}
	return AnyEntityType{}
}

func (s *Schema) parseSetType(element *jsonType) (CedarType, error) {
	if element != nil {
		elem, err := s.parseJSONType(element)
		if err != nil {
			return nil, err
		}
		return SetType{Element: elem}, nil
	}
	return SetType{Element: UnknownType{}}, nil
}

func (s *Schema) parseRecordType(attributes map[string]jsonAttr) (CedarType, error) {
	rec := RecordType{Attributes: make(map[string]AttributeType)}
	for name, attr := range attributes {
		at, err := s.parseJSONAttr(&attr)
		if err != nil {
			return nil, err
		}
		rec.Attributes[name] = at
	}
	return rec, nil
}

func (s *Schema) parseRecordTypeWithOpen(jt *jsonType) (RecordType, error) {
	rec := RecordType{Attributes: make(map[string]AttributeType)}
	if jt == nil {
		return rec, nil
	}
	for name, attr := range jt.Attributes {
		at, err := s.parseJSONAttr(&attr)
		if err != nil {
			return rec, err
		}
		rec.Attributes[name] = at
	}
	return rec, nil
}

func (s *Schema) parseExtensionType(name string) CedarType {
	if name != "" {
		return ExtensionType{Name: name}
	}
	return UnknownType{}
}

func (s *Schema) parseTypeReference(typeName string) (CedarType, error) {
	if ct, ok := s.commonTypes[typeName]; ok {
		return ct, nil
	}
	if typeName != "" {
		if !isValidParseTypeReference(typeName) {
			return UnspecifiedType{}, nil
		}
		return EntityCedarType{Name: types.EntityType(typeName)}, nil
	}
	return UnspecifiedType{}, nil
}

func isValidParseTypeReference(name string) bool {
	if name == "" {
		return false
	}
	parts := strings.Split(name, "::")
	for _, part := range parts {
		if !isValidParseCedarIdent(part) {
			return false
		}
	}
	return true
}

func isValidParseCedarIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '_') {
				return false
			}
		} else {
			if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_') {
				return false
			}
		}
	}
	return true
}

func (s *Schema) parseJSONAttr(ja *jsonAttr) (AttributeType, error) {
	required := true
	if ja.Required != nil {
		required = *ja.Required
	}

	ct, err := s.parseAttrType(ja)
	if err != nil {
		return AttributeType{}, err
	}

	return AttributeType{Type: ct, Required: required}, nil
}

func (s *Schema) parseAttrType(ja *jsonAttr) (CedarType, error) {
	switch ja.Type {
	case "Boolean", "Bool":
		return BoolType{}, nil
	case "Long":
		return LongType{}, nil
	case "String":
		return StringType{}, nil
	case "Entity":
		return s.parseEntityRefType(ja.Name), nil
	case "Set":
		return s.parseSetType(ja.Element)
	case "Record":
		return s.parseRecordType(ja.Attributes)
	case "Extension":
		return s.parseExtensionType(ja.Name), nil
	default:
		return s.parseTypeReference(ja.Type)
	}
}
