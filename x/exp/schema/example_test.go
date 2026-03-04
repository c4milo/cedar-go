package schema_test

import (
	"fmt"

	"github.com/cedar-policy/cedar-go/x/exp/schema"
)

const exampleCedar = `entity User in [Group] {
	name: String,
	age?: Long
};

entity Group;

entity Photo {
	owner: User,
	tags: Set<String>
};

entity Status enum ["active", "inactive"];

action viewPhoto appliesTo {
	principal: User,
	resource: Photo,
	context: {}
};
`

func ExampleSchema() {
	s, err := schema.NewFromCedar("", []byte(exampleCedar))
	if err != nil {
		fmt.Println("schema parse error:", err)
		return
	}

	resolved, err := s.Resolve()
	if err != nil {
		fmt.Println("schema resolve error:", err)
		return
	}

	for entityType := range resolved.Entities {
		fmt.Println("entity:", entityType)
	}
	for _, enum := range resolved.Enums {
		fmt.Println("enum:", enum.Name)
	}
	for actionUID := range resolved.Actions {
		fmt.Println("action:", actionUID)
	}
	// Unordered output:
	// entity: User
	// entity: Group
	// entity: Photo
	// enum: Status
	// action: Action::"viewPhoto"
}
