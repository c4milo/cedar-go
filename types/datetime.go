package types

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
	"unicode"

	"github.com/cedar-policy/cedar-go/internal"
)

var errDatetime = internal.ErrDatetime

// maxDatetime is the highest possible timestamp that will fit in 64 bits of millisecond-precision space.
var maxDatetime = time.Date(292278994, 8, 17, 7, 12, 55, 807*1e6, time.UTC)

// minDatetime is the lowest possible timestamp that will fit in 64 bits of millisecond-precision space.
var minDatetime = time.Date(-292275055, 5, 17, 16, 47, 04, 192*1e6, time.UTC)

// Datetime represents a Cedar datetime value
type Datetime struct {
	// value is a timestamp in milliseconds
	value int64
}

// NewDatetime returns a Cedar Datetime from a Go time.Time value.
//
// The provided time.Time is truncated to millisecond precision. The result is
// undefined if the Unix time in milliseconds cannot be represented by an int64
// (a date more than 292 million years before or after 1970).
func NewDatetime(t time.Time) Datetime {
	return Datetime{value: t.UnixMilli()}
}

// NewDatetimeFromMillis returns a Datetime from a count of milliseconds since
// January 1, 1970 @ 00:00:00 UTC.
func NewDatetimeFromMillis(ms int64) Datetime {
	return Datetime{value: ms}
}

func expectChar(s string, c uint8) (string, error) {
	if len(s) == 0 {
		return "", fmt.Errorf("%w: unexpected EOF", errDatetime)
	} else if s[0] != c {
		return "", fmt.Errorf("%w: unexpected character %c", errDatetime, s[0])
	}
	return s[1:], nil
}

func parseUint(s string, chars int, maxValue uint, label string) (uint, string, error) {
	if len(s) < chars {
		return 0, "", fmt.Errorf("%w: unexpected EOF", errDatetime)
	}
	v, err := strconv.ParseUint(s[0:chars], 10, 0)
	if err != nil {
		return 0, "", fmt.Errorf("%w: invalid %v", errDatetime, label)
	} else if v > uint64(maxValue) {
		return 0, "", fmt.Errorf("%w: %v is greater than %v", errDatetime, label, maxValue)
	}
	return uint(v), s[chars:], nil
}

// checkValidDay ensures that the given day is valid for the given month in the given year.
func checkValidDay(year int, month, day uint) error {
	t := time.Date(year, time.Month(month), int(day), 0, 0, 0, 0, time.UTC)

	// Don't allow wrapping: https://github.com/cedar-policy/rfcs/pull/94
	_, tmonth, tday := t.Date()
	if time.Month(month) != tmonth || int(day) != tday {
		return fmt.Errorf("%w: invalid date", errDatetime)
	}

	return nil
}

// datetimeParseState holds intermediate parsing state for datetime strings.
type datetimeParseState struct {
	year, month, day     int
	hour, minute, second uint
	milli                uint
	offset               time.Duration
	remaining            string
}

// parseYear parses the year portion of a datetime string, handling both
// standard (4-digit) and expanded (9-digit with sign) formats.
func parseYear(s string) (year int, remaining string, err error) {
	if len(s) == 0 {
		return 0, "", fmt.Errorf("%w: unexpected EOF", errDatetime)
	}

	yearSign := 1
	yearLength := 4
	yearMax := uint(9999)

	if s[0] == '+' || s[0] == '-' {
		yearLength = 9
		yearMax = 999999999
		if s[0] == '-' {
			yearSign = -1
		}
		s = s[1:]
	} else if !unicode.IsDigit(rune(s[0])) {
		return 0, "", fmt.Errorf("%w: invalid year", errDatetime)
	}

	absYear, s, err := parseUint(s, yearLength, yearMax, "year")
	if err != nil {
		return 0, "", err
	}

	return int(absYear) * yearSign, s, nil
}

// parseDate parses month and day from the datetime string.
func parseDate(s string) (month, day uint, remaining string, err error) {
	if s, err = expectChar(s, '-'); err != nil {
		return 0, 0, "", err
	}

	if month, s, err = parseUint(s, 2, 12, "month"); err != nil {
		return 0, 0, "", err
	}

	if s, err = expectChar(s, '-'); err != nil {
		return 0, 0, "", err
	}

	if day, s, err = parseUint(s, 2, 31, "day"); err != nil {
		return 0, 0, "", err
	}

	return month, day, s, nil
}

// parseTimeComponents parses hour, minute, second from the datetime string.
func parseTimeComponents(s string) (hour, minute, second uint, remaining string, err error) {
	if s, err = expectChar(s, 'T'); err != nil {
		return 0, 0, 0, "", err
	}

	if hour, s, err = parseUint(s, 2, 23, "hour"); err != nil {
		return 0, 0, 0, "", err
	}

	if s, err = expectChar(s, ':'); err != nil {
		return 0, 0, 0, "", err
	}

	if minute, s, err = parseUint(s, 2, 59, "minute"); err != nil {
		return 0, 0, 0, "", err
	}

	if s, err = expectChar(s, ':'); err != nil {
		return 0, 0, 0, "", err
	}

	if second, s, err = parseUint(s, 2, 59, "second"); err != nil {
		return 0, 0, 0, "", err
	}

	return hour, minute, second, s, nil
}

// parseMilliseconds parses optional milliseconds from the datetime string.
func parseMilliseconds(s string) (milli uint, remaining string, err error) {
	if len(s) > 0 && s[0] == '.' {
		milli, s, err = parseUint(s[1:], 3, 999, "millisecond")
		if err != nil {
			return 0, "", err
		}
	}
	return milli, s, nil
}

// parseTimezone parses the timezone designator (Z or +/-hhmm) from the datetime string.
func parseTimezone(s string) (offset time.Duration, remaining string, err error) {
	if len(s) == 0 {
		return 0, "", fmt.Errorf("%w: unexpected EOF", errDatetime)
	}

	switch s[0] {
	case 'Z':
		return 0, s[1:], nil
	case '+', '-':
		sign := 1
		if s[0] == '-' {
			sign = -1
		}
		s = s[1:]

		var hh uint
		if hh, s, err = parseUint(s, 2, 23, "offset hours"); err != nil {
			return 0, "", err
		}

		var mm uint
		if mm, s, err = parseUint(s, 2, 59, "offset minutes"); err != nil {
			return 0, "", err
		}

		offset = time.Duration(sign) * ((time.Duration(hh) * time.Hour) + (time.Duration(mm) * time.Minute))
		return offset, s, nil
	default:
		return 0, "", fmt.Errorf("%w: invalid time zone designator", errDatetime)
	}
}

// ParseDatetime returns a Cedar datetime when the argument provided
// represents a compatible datetime or an error
//
// Cedar RFC 80 defines valid datetime strings as one of:
//
// - "YYYY-MM-DD" (date only, with implied time 00:00:00, UTC)
// - "YYYY-MM-DDThh:mm:ssZ" (date and time, UTC)
// - "YYYY-MM-DDThh:mm:ss.SSSZ" (date and time with millisecond, UTC)
// - "YYYY-MM-DDThh:mm:ss(+/-)hhmm" (date and time, time zone offset)
// - "YYYY-MM-DDThh:mm:ss.SSS(+/-)hhmm" (date and time with millisecond, time zone offset)
//
// Cedar RFC 110 extends this with ISO 8601 expanded year format:
//
// - "(+/-)YYYYYYYYY-MM-DD" (9-digit year, date only)
// - "(+/-)YYYYYYYYY-MM-DDThh:mm:ssZ" (9-digit year, date and time, UTC)
// - "(+/-)YYYYYYYYY-MM-DDThh:mm:ss.SSSZ" (9-digit year with millisecond, UTC)
// - "(+/-)YYYYYYYYY-MM-DDThh:mm:ss(+/-)hhmm" (9-digit year with time zone offset)
// - "(+/-)YYYYYYYYY-MM-DDThh:mm:ss.SSS(+/-)hhmm" (9-digit year with millisecond and offset)
func ParseDatetime(s string) (Datetime, error) {
	var state datetimeParseState
	var err error

	// Parse year
	state.year, state.remaining, err = parseYear(s)
	if err != nil {
		return Datetime{}, err
	}

	// Parse month and day
	month, day, remaining, err := parseDate(state.remaining)
	if err != nil {
		return Datetime{}, err
	}
	state.month = int(month)
	state.day = int(day)
	state.remaining = remaining

	if err = checkValidDay(state.year, uint(state.month), uint(state.day)); err != nil {
		return Datetime{}, err
	}

	// Date-only format
	if len(state.remaining) == 0 {
		return Datetime{time.Date(state.year, time.Month(state.month), state.day, 0, 0, 0, 0, time.UTC).UnixMilli()}, nil
	}

	// Parse time components
	state.hour, state.minute, state.second, state.remaining, err = parseTimeComponents(state.remaining)
	if err != nil {
		return Datetime{}, err
	}

	if len(state.remaining) == 0 {
		return Datetime{}, fmt.Errorf("%w: unexpected EOF", errDatetime)
	}

	// Parse optional milliseconds
	state.milli, state.remaining, err = parseMilliseconds(state.remaining)
	if err != nil {
		return Datetime{}, err
	}

	// Parse timezone
	state.offset, state.remaining, err = parseTimezone(state.remaining)
	if err != nil {
		return Datetime{}, err
	}

	if len(state.remaining) > 0 {
		return Datetime{}, fmt.Errorf("%w: unexpected additional characters", errDatetime)
	}

	t := time.Date(state.year, time.Month(state.month), state.day,
		int(state.hour), int(state.minute), int(state.second),
		int(time.Duration(state.milli)*time.Millisecond), time.UTC).Add(-state.offset)

	// Check for boundary conditions before calling UnixMilli(), which has undefined behavior outside of these
	// boundaries
	if t.Before(minDatetime) || t.After(maxDatetime) {
		return Datetime{}, fmt.Errorf("%w: timestamp out of range", errDatetime)
	}

	return Datetime{value: t.UnixMilli()}, nil
}

// Equal returns true if the input represents the same timestamp.
func (d Datetime) Equal(bi Value) bool {
	b, ok := bi.(Datetime)
	return ok && d == b
}

// LessThan returns true if value is less than the argument and they
// are both Datetime values, or an error indicating they aren't
// comparable otherwise
func (d Datetime) LessThan(bi Value) (bool, error) {
	b, ok := bi.(Datetime)
	if !ok {
		return false, internal.ErrNotComparable
	}
	return d.value < b.value, nil
}

// LessThanOrEqual returns true if value is less than or equal to the
// argument and they are both Datetime values, or an error indicating
// they aren't comparable otherwise
func (d Datetime) LessThanOrEqual(bi Value) (bool, error) {
	b, ok := bi.(Datetime)
	if !ok {
		return false, internal.ErrNotComparable
	}
	return d.value <= b.value, nil
}

// MarshalCedar returns a []byte which, when parsed by the Cedar
// Parser, returns an Equal Datetime value
func (d Datetime) MarshalCedar() []byte {
	return []byte(`datetime("` + d.String() + `")`)
}

// String returns an ISO 8601 millisecond precision timestamp.
// For years in [0000, 9999], returns RFC 3339 format: "YYYY-MM-DDThh:mm:ss.SSSZ"
// For years outside that range, returns expanded year format: "(+/-)YYYYYYYYY-MM-DDThh:mm:ss.SSSZ"
func (d Datetime) String() string {
	t := time.UnixMilli(d.value).UTC()
	year := t.Year()

	// Use RFC 3339 format for years in standard range
	if year >= 0 && year <= 9999 {
		return t.Format("2006-01-02T15:04:05.000Z")
	}

	// Use ISO 8601 expanded year format for years outside standard range
	sign := '+'
	if year < 0 {
		sign = '-'
		year = -year
	}

	return fmt.Sprintf("%c%09d-%02d-%02dT%02d:%02d:%02d.%03dZ",
		sign, year, t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second(), t.Nanosecond()/1e6)
}

// UnmarshalJSON implements encoding/json.Unmarshaler for Datetime
//
// It is capable of unmarshaling 3 different representations supported by Cedar
//   - { "__extn": { "fn": "datetime", "arg": "1970-01-01" }}
//   - { "fn": "datetime", "arg": "1970-01-01" }
//   - "1970-01-01"
func (d *Datetime) UnmarshalJSON(b []byte) error {
	aa, err := unmarshalExtensionValue(b, "datetime", ParseDatetime)
	if err != nil {
		return err
	}

	*d = aa
	return nil
}

// MarshalJSON marshals a Cedar Datetime with the explicit representation
func (d Datetime) MarshalJSON() ([]byte, error) {
	return json.Marshal(extValueJSON{
		Extn: &extn{
			Fn:  "datetime",
			Arg: d.String(),
		},
	})
}

// Milliseconds returns the number of milliseconds since the Unix epoch
func (d Datetime) Milliseconds() int64 {
	return d.value
}

// Time returns the UTC time.Time representation of a Datetime.
func (d Datetime) Time() time.Time {
	return time.UnixMilli(d.value).UTC()
}

func (d Datetime) hash() uint64 {
	return uint64(d.value)
}
