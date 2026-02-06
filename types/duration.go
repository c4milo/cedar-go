package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"
	"unicode"

	"github.com/cedar-policy/cedar-go/internal"
	"github.com/cedar-policy/cedar-go/internal/consts"
)

var errDuration = internal.ErrDuration

var unitToMillis = map[string]int64{
	"d":  consts.MillisPerDay,
	"h":  consts.MillisPerHour,
	"m":  consts.MillisPerMinute,
	"s":  consts.MillisPerSecond,
	"ms": 1,
}

var unitOrder = []string{"d", "h", "m", "s", "ms"}

// A Duration is a value representing a span of time in milliseconds.
type Duration struct {
	value int64
}

// NewDuration returns a Cedar Duration from a Go time.Duration
func NewDuration(d time.Duration) Duration {
	return Duration{value: d.Milliseconds()}
}

// NewDurationFromMillis returns a Duration from milliseconds
func NewDurationFromMillis(ms int64) Duration {
	return Duration{value: ms}
}

// durationParseState holds the parsing state for duration strings.
type durationParseState struct {
	i        int
	unitI    int
	total    int64
	value    int64
	hasValue bool
}

// parseDigit processes a digit character and updates the parse state.
// Returns an error if overflow occurs.
func (s *durationParseState) parseDigit(c byte) error {
	s.value = s.value*10 + int64(c-'0')
	if s.value > math.MaxInt32 {
		return fmt.Errorf("%w: overflow", errDuration)
	}
	s.hasValue = true
	s.i++
	return nil
}

// parseUnit processes a unit character and updates the parse state.
// Returns the unit string and any error encountered.
func (s *durationParseState) parseUnit(str string) (string, error) {
	if !s.hasValue {
		return "", fmt.Errorf("%w: unit found without quantity", errDuration)
	}

	var unit string
	// Check for "ms" unit
	if str[s.i] == 'm' && s.i+1 < len(str) && str[s.i+1] == 's' {
		unit = "ms"
		s.i++
	} else {
		unit = str[s.i : s.i+1]
	}

	// Validate unit order
	unitOK := false
	for !unitOK && s.unitI < len(unitOrder) {
		if unit == unitOrder[s.unitI] {
			unitOK = true
		}
		s.unitI++
	}

	if !unitOK {
		return "", fmt.Errorf("%w: unexpected unit '%s'", errDuration, unit)
	}

	s.total = s.total + s.value*unitToMillis[unit]
	s.i++
	s.hasValue = false
	s.value = 0

	return unit, nil
}

// parseNextToken processes the next character in the duration string.
// Returns an error if the character is invalid.
func (s *durationParseState) parseNextToken(str string) error {
	c := str[s.i]
	if unicode.IsDigit(rune(c)) {
		return s.parseDigit(c)
	}
	if c == 'd' || c == 'h' || c == 'm' || c == 's' {
		_, err := s.parseUnit(str)
		return err
	}
	return fmt.Errorf("%w: unexpected character %s", errDuration, strconv.QuoteRune(rune(c)))
}

// ParseDuration parses a Cedar Duration from a string
//
// Cedar RFC 80 defines a valid duration string as collapsed sequence
// of quantity-unit pairs, possibly with a leading `-`, indicating a
// negative duration.
// The units must appear in order from longest timeframe to smallest.
// - d: days
// - h: hours
// - m: minutes
// - s: seconds
// - ms: milliseconds
func ParseDuration(s string) (Duration, error) {
	// Check for empty string.
	if len(s) <= 1 {
		return Duration{}, fmt.Errorf("%w: string too short", errDuration)
	}

	state := &durationParseState{}

	negative := int64(1)
	if s[state.i] == '-' {
		negative = int64(-1)
		state.i++
	}

	// ([0-9]+)(d|h|m|s|ms) ...
	for state.i < len(s) && state.unitI < len(unitOrder) {
		if err := state.parseNextToken(s); err != nil {
			return Duration{}, err
		}
	}

	// We didn't have a trailing unit
	if state.hasValue {
		return Duration{}, fmt.Errorf("%w: expected unit", errDuration)
	}

	// We still have characters left, but no more units to assign.
	if state.i < len(s) {
		return Duration{}, fmt.Errorf("%w: invalid duration", errDuration)
	}

	return Duration{value: negative * state.total}, nil
}

// Equal returns true if the input represents the same duration
func (d Duration) Equal(bi Value) bool {
	b, ok := bi.(Duration)
	return ok && d == b
}

// LessThan returns true if value is less than the argument and they
// are both Duration values, or an error indicating they aren't
// comparable otherwise
func (d Duration) LessThan(bi Value) (bool, error) {
	b, ok := bi.(Duration)
	if !ok {
		return false, internal.ErrNotComparable
	}
	return d.value < b.value, nil
}

// LessThan returns true if value is less than or equal to the
// argument and they are both Duration values, or an error indicating
// they aren't comparable otherwise
func (d Duration) LessThanOrEqual(bi Value) (bool, error) {
	b, ok := bi.(Duration)
	if !ok {
		return false, internal.ErrNotComparable
	}
	return d.value <= b.value, nil
}

// MarshalCedar produces a valid MarshalCedar language representation of the Duration, e.g. `decimal("12.34")`.
func (d Duration) MarshalCedar() []byte { return []byte(`duration("` + d.String() + `")`) }

// String produces a string representation of the Duration
func (d Duration) String() string {
	var res bytes.Buffer
	if d.value == 0 {
		return "0ms"
	}

	remaining := d.value
	if d.value < 0 {
		remaining = -d.value
		res.WriteByte('-')
	}

	days := remaining / consts.MillisPerDay
	if days > 0 {
		res.WriteString(strconv.FormatInt(days, 10))
		res.WriteByte('d')
	}
	remaining %= consts.MillisPerDay

	hours := remaining / consts.MillisPerHour
	if hours > 0 {
		res.WriteString(strconv.FormatInt(hours, 10))
		res.WriteByte('h')
	}
	remaining %= consts.MillisPerHour

	minutes := remaining / consts.MillisPerMinute
	if minutes > 0 {
		res.WriteString(strconv.FormatInt(minutes, 10))
		res.WriteByte('m')
	}
	remaining %= consts.MillisPerMinute

	seconds := remaining / consts.MillisPerSecond
	if seconds > 0 {
		res.WriteString(strconv.FormatInt(seconds, 10))
		res.WriteByte('s')
	}
	remaining %= consts.MillisPerSecond

	if remaining > 0 {
		res.WriteString(strconv.FormatInt(remaining, 10))
		res.WriteString("ms")
	}

	return res.String()
}

// UnmarshalJSON implements encoding/json.Unmarshaler for Duration
//
// It is capable of unmarshaling 3 different representations supported by Cedar
//   - { "__extn": { "fn": "duration", "arg": "1h10m" }}
//   - { "fn": "duration", "arg": "1h10m" }
//   - "1h10m"
func (d *Duration) UnmarshalJSON(b []byte) error {
	vv, err := unmarshalExtensionValue(b, "duration", ParseDuration)
	if err != nil {
		return err
	}

	*d = vv
	return nil
}

// MarshalJSON marshals the Duration into JSON using the explicit form.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(extValueJSON{
		Extn: &extn{
			Fn:  "duration",
			Arg: d.String(),
		},
	})
}

// ToDays returns the number of days this Duration represents,
// truncating when fractional
func (d Duration) ToDays() int64 {
	return d.value / consts.MillisPerDay
}

// ToHours returns the number of hours this Duration represents,
// truncating when fractional
func (d Duration) ToHours() int64 {
	return d.value / consts.MillisPerHour
}

// ToMinutes returns the number of minutes this Duration represents,
// truncating when fractional
func (d Duration) ToMinutes() int64 {
	return d.value / consts.MillisPerMinute
}

// ToSeconds returns the number of seconds this Duration represents,
// truncating when fractional
func (d Duration) ToSeconds() int64 {
	return d.value / consts.MillisPerSecond
}

// ToMilliseconds returns the number of milliseconds this Duration
// represents
func (d Duration) ToMilliseconds() int64 {
	return d.value
}

// Duration returns a time.Duration representation of a Duration.  An error
// is returned if the duration cannot be converted to a time.Duration.
func (d Duration) Duration() (time.Duration, error) {
	if d.value > math.MaxInt64/1000 {
		return 0, internal.ErrDurationRange
	}
	if d.value < math.MinInt64/1000 {
		return 0, internal.ErrDurationRange
	}
	return time.Millisecond * time.Duration(d.value), nil
}

func (d Duration) hash() uint64 {
	return uint64(d.value)
}
