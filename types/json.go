package types

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	errJSONInvalidExtn     = fmt.Errorf("invalid extension")
	errJSONDecode          = fmt.Errorf("error decoding json")
	errJSONLongOutOfRange  = fmt.Errorf("long out of range")
	errJSONUnsupportedType = fmt.Errorf("unsupported type")
	errJSONExtFnMatch      = fmt.Errorf("json extn mismatch")
	errJSONExtNotFound     = fmt.Errorf("json extn not found")
	errJSONEntityNotFound  = fmt.Errorf("json entity not found")
)

type extn struct {
	Fn  string `json:"fn"`
	Arg string `json:"arg"`
}

type extValueJSON struct {
	Extn *extn `json:"__extn,omitempty"`
}

type extEntity struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type entityValueJSON struct {
	Type   *string    `json:"type,omitempty"`
	ID     *string    `json:"id,omitempty"`
	Entity *extEntity `json:"__entity,omitempty"`
}

type explicitValue struct {
	Value Value
}

// unmarshalExtensionFromJSON attempts to unmarshal an extension value from JSON.
// Returns the parsed value and true if successful, or zero value and false if not an extension.
func unmarshalExtensionFromJSON(b []byte) (Value, bool, error) {
	var res extValueJSON
	if err := json.Unmarshal(b, &res); err != nil || res.Extn == nil {
		return nil, false, nil
	}

	switch res.Extn.Fn {
	case "ip":
		val, err := ParseIPAddr(res.Extn.Arg)
		if err != nil {
			return nil, true, err
		}
		return val, true, nil
	case "decimal":
		val, err := ParseDecimal(res.Extn.Arg)
		if err != nil {
			return nil, true, err
		}
		return val, true, nil
	case "datetime":
		val, err := ParseDatetime(res.Extn.Arg)
		if err != nil {
			return nil, true, err
		}
		return val, true, nil
	case "duration":
		val, err := ParseDuration(res.Extn.Arg)
		if err != nil {
			return nil, true, err
		}
		return val, true, nil
	default:
		return nil, true, errJSONInvalidExtn
	}
}

// unmarshalPrimitiveFromJSON unmarshals primitive JSON values (string, bool, number).
func unmarshalPrimitiveFromJSON(b []byte) (Value, error) {
	var res any
	dec := json.NewDecoder(bytes.NewBuffer(b))
	dec.UseNumber()
	if err := dec.Decode(&res); err != nil {
		return nil, fmt.Errorf("%w: %w", errJSONDecode, err)
	}

	switch vv := res.(type) {
	case string:
		return String(vv), nil
	case bool:
		return Boolean(vv), nil
	case json.Number:
		l, err := vv.Int64()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errJSONLongOutOfRange, err)
		}
		return Long(l), nil
	default:
		return nil, errJSONUnsupportedType
	}
}

func UnmarshalJSON(b []byte, v *Value) error {
	// Try entity UID first
	{
		var res EntityUID
		ptr := &res
		if err := ptr.UnmarshalJSON(b); err == nil {
			*v = res
			return nil
		}
	}

	// Try extension value
	if val, isExt, err := unmarshalExtensionFromJSON(b); isExt {
		if err != nil {
			return err
		}
		*v = val
		return nil
	}

	// Try compound types (array/object)
	if len(b) > 0 {
		switch b[0] {
		case '[':
			var res Set
			err := json.Unmarshal(b, &res)
			*v = res
			return err
		case '{':
			res := Record{}
			err := json.Unmarshal(b, &res)
			*v = res
			return err
		}
	}

	// Try primitives
	val, err := unmarshalPrimitiveFromJSON(b)
	if err != nil {
		return err
	}
	*v = val
	return nil
}

// unmarshalExtensionArg extracts the extension argument from JSON bytes.
func unmarshalExtensionArg(b []byte, extName string) (string, error) {
	// Check if it's a simple string
	if len(b) > 0 && b[0] == '"' {
		var arg string
		if err := json.Unmarshal(b, &arg); err != nil {
			return "", errors.Join(errJSONDecode, err)
		}
		return arg, nil
	}

	// Try __extn format first
	var res extValueJSON
	if err := json.Unmarshal(b, &res); err != nil {
		return "", errors.Join(errJSONDecode, err)
	}

	if res.Extn != nil {
		if res.Extn.Fn != extName {
			return "", errJSONExtFnMatch
		}
		return res.Extn.Arg, nil
	}

	// Try bare extn format
	var res2 extn
	if err := json.Unmarshal(b, &res2); err != nil {
		return "", errors.Join(errJSONDecode, err)
	}

	if res2.Fn == "" {
		return "", errJSONExtNotFound
	}
	if res2.Fn != extName {
		return "", errJSONExtFnMatch
	}
	return res2.Arg, nil
}

func unmarshalExtensionValue[T any](b []byte, extName string, parse func(string) (T, error)) (T, error) {
	var zeroT T

	arg, err := unmarshalExtensionArg(b, extName)
	if err != nil {
		return zeroT, err
	}

	v, err := parse(arg)
	if err != nil {
		return zeroT, err
	}

	return v, nil
}
