package conformance

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/murmur-protocol/murmur-go/cbor"
)

// parseValue turns the tagged-JSON `value` of a vector into a cbor.Value.
// Plain JSON is the native subset (integer, string, boolean, array, text-keyed
// map), and four single-key tag objects reach the rest: $bytes, $decimal,
// $rational, $map. A single-key object whose key begins with "$" but is not a
// registered tag is an error, never a literal.
func parseValue(raw json.RawMessage) (cbor.Value, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep integers exact; never via float64
	var x any
	if err := dec.Decode(&x); err != nil {
		return nil, err
	}
	return walk(x)
}

func walk(x any) (cbor.Value, error) {
	switch t := x.(type) {
	case json.Number:
		return intFromNumber(t)
	case string:
		return cbor.Text{V: t}, nil
	case bool:
		return cbor.Bool{V: t}, nil
	case []any:
		items := make([]cbor.Value, 0, len(t))
		for _, e := range t {
			v, err := walk(e)
			if err != nil {
				return nil, err
			}
			items = append(items, v)
		}
		return cbor.Array{Items: items}, nil
	case map[string]any:
		return walkObject(t)
	case nil:
		return nil, fmt.Errorf("null has no canonical form")
	default:
		return nil, fmt.Errorf("unexpected JSON value %T", x)
	}
}

// walkObject handles both a registered tag (a single key beginning with "$")
// and a plain text-keyed map (every other object).
func walkObject(obj map[string]any) (cbor.Value, error) {
	if len(obj) == 1 {
		for k, v := range obj {
			if strings.HasPrefix(k, "$") {
				return walkTag(k, v)
			}
		}
	}
	entries := make([]cbor.MapEntry, 0, len(obj))
	for k, v := range obj {
		if strings.HasPrefix(k, "$") {
			return nil, fmt.Errorf("object key %q begins with $ but is not a registered tag", k)
		}
		val, err := walk(v)
		if err != nil {
			return nil, err
		}
		entries = append(entries, cbor.MapEntry{Key: cbor.Text{V: k}, Value: val})
	}
	return cbor.Map{Entries: entries}, nil
}

func walkTag(tag string, v any) (cbor.Value, error) {
	switch tag {
	case "$bytes":
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("$bytes wants a hex string")
		}
		raw, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("$bytes: %w", err)
		}
		return cbor.Bytes{V: raw}, nil
	case "$decimal":
		a, b, err := twoInts(tag, v)
		if err != nil {
			return nil, err
		}
		return cbor.Decimal{Scale: a, Mantissa: b}, nil
	case "$rational":
		a, b, err := twoInts(tag, v)
		if err != nil {
			return nil, err
		}
		return cbor.Rational{Num: a, Den: b}, nil
	case "$map":
		return walkMapPairs(v)
	default:
		return nil, fmt.Errorf("unknown tag %q", tag)
	}
}

// walkMapPairs reads the {"$map": [[key, value], ...]} form, the way to give a
// map with non-text (integer) keys, which a JSON object cannot express.
func walkMapPairs(v any) (cbor.Value, error) {
	pairs, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("$map wants an array of pairs")
	}
	entries := make([]cbor.MapEntry, 0, len(pairs))
	for _, p := range pairs {
		pair, ok := p.([]any)
		if !ok || len(pair) != 2 {
			return nil, fmt.Errorf("$map entry must be a two-element [key, value] array")
		}
		key, err := walk(pair[0])
		if err != nil {
			return nil, err
		}
		val, err := walk(pair[1])
		if err != nil {
			return nil, err
		}
		entries = append(entries, cbor.MapEntry{Key: key, Value: val})
	}
	return cbor.Map{Entries: entries}, nil
}

func twoInts(tag string, v any) (*big.Int, *big.Int, error) {
	arr, ok := v.([]any)
	if !ok || len(arr) != 2 {
		return nil, nil, fmt.Errorf("%s wants a two-element integer array", tag)
	}
	a, err := bigFromAny(arr[0])
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", tag, err)
	}
	b, err := bigFromAny(arr[1])
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", tag, err)
	}
	return a, b, nil
}

func bigFromAny(x any) (*big.Int, error) {
	n, ok := x.(json.Number)
	if !ok {
		return nil, fmt.Errorf("want an integer, got %T", x)
	}
	return bigFromNumber(n)
}

func intFromNumber(n json.Number) (cbor.Value, error) {
	b, err := bigFromNumber(n)
	if err != nil {
		return nil, err
	}
	return cbor.Int{V: b}, nil
}

// bigFromNumber parses a JSON number as an exact integer. A fractional or
// exponential literal is rejected: the canonical value domain has no floats.
func bigFromNumber(n json.Number) (*big.Int, error) {
	b, ok := new(big.Int).SetString(n.String(), 10)
	if !ok {
		return nil, fmt.Errorf("%q is not an integer", n.String())
	}
	return b, nil
}
