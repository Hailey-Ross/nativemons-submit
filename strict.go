package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// parseStrict reads one JSON object of exactly the fields in fields: every one present once, nothing
// else, no duplicates, nothing after it. Each value goes into the pointer given for its name.
func parseStrict(body []byte, fields map[string]any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return errors.New("not an object")
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return errors.New("bad field name")
		}
		name, ok := tok.(string)
		if !ok {
			return errors.New("bad field name")
		}
		target, known := fields[name]
		if !known {
			return errors.New("unknown field")
		}
		if seen[name] {
			return errors.New("field given twice")
		}
		seen[name] = true
		if err := dec.Decode(target); err != nil {
			return errors.New("bad value for a field")
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return errors.New("object not closed")
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data after the object")
	}
	if len(seen) != len(fields) {
		return errors.New("a field is missing")
	}
	return nil
}
