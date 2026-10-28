// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// goldenEvents loads library/tests/fixtures/events_golden.json: one sample of
// every event exactly as the FFI delivers it, with every optional field
// present and set to a non-default value (except the deliberate null ids).
// Numbers are kept as json.Number so u64 values compare exactly.
func goldenEvents(t *testing.T) (raw []json.RawMessage, parsed []map[string]any) {
	t.Helper()
	data, err := os.ReadFile("../../../library/tests/fixtures/events_golden.json")
	if err != nil {
		t.Fatalf("read events_golden.json: %v", err)
	}
	var doc struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse events_golden.json: %v", err)
	}
	for i, ev := range doc.Events {
		dec := json.NewDecoder(bytes.NewReader(ev))
		dec.UseNumber()
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("parse event %d: %v", i, err)
		}
		parsed = append(parsed, m)
	}
	return doc.Events, parsed
}

// eventTypeConstants returns every EventType* constant declared in events.go,
// read from the source so a constant added or removed there is seen here.
func eventTypeConstants(t *testing.T) map[string]string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "events.go", nil, 0)
	if err != nil {
		t.Fatalf("parse events.go: %v", err)
	}
	out := map[string]string{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "EventType") || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Fatalf("%s is not a string literal", name.Name)
				}
				value, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("%s: %v", name.Name, err)
				}
				out[value] = name.Name
			}
		}
	}
	return out
}

// eventFieldOverrides names the Event fields decoded through UnmarshalJSON's
// aux struct rather than their own json tag.
var eventFieldOverrides = map[string]string{
	"kind":        "Kind",
	"sender_kind": "SenderKind",
}

// compareByMarshal lists types whose wire form is a name rather than their Go
// representation, so they are compared through their own MarshalJSON.
var compareByMarshal = map[reflect.Type]bool{
	reflect.TypeOf(EndpointJSON{}): true,
}

var marshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()

type goldenWalker struct {
	t *testing.T
	// seen records every struct field the fixture populated, per type.
	seen map[reflect.Type]map[string]bool
}

func (w *goldenWalker) fail(path string, format string, args ...any) {
	w.t.Helper()
	w.t.Errorf("%s: %s", path, fmt.Sprintf(format, args...))
}

func (w *goldenWalker) fieldsByTag(typ reflect.Type) map[string]int {
	out := map[string]int{}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		out[tag] = i
	}
	if typ == reflect.TypeOf(Event{}) {
		for key, name := range eventFieldOverrides {
			f, ok := typ.FieldByName(name)
			if !ok {
				w.t.Fatalf("Event has no field %s", name)
			}
			out[key] = f.Index[0]
		}
	}
	return out
}

func (w *goldenWalker) compare(path string, want any, got reflect.Value) {
	w.t.Helper()
	if want == nil {
		switch got.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Map, reflect.Interface:
			if !got.IsNil() {
				w.fail(path, "fixture is null, Go has %v", got.Elem())
			}
		default:
			w.fail(path, "fixture is null, Go field of type %s cannot be nil", got.Type())
		}
		return
	}
	if got.Kind() == reflect.Pointer {
		if got.IsNil() {
			w.fail(path, "Go is nil, fixture has %v", want)
			return
		}
		got = got.Elem()
	}

	switch want := want.(type) {
	case map[string]any:
		switch {
		case got.Kind() == reflect.Map:
			if got.Len() != len(want) {
				w.fail(path, "Go map has %d entries, fixture has %d", got.Len(), len(want))
			}
			for k, v := range want {
				entry := got.MapIndex(reflect.ValueOf(k))
				if !entry.IsValid() {
					w.fail(path+"."+k, "missing from Go map")
					continue
				}
				w.compare(path+"."+k, v, entry)
			}
		case got.Kind() == reflect.Struct && compareByMarshal[got.Type()]:
			w.compareMarshaled(path, want, got)
		case got.Kind() == reflect.Struct:
			typ := got.Type()
			fields := w.fieldsByTag(typ)
			if w.seen[typ] == nil {
				w.seen[typ] = map[string]bool{}
			}
			for k, v := range want {
				idx, ok := fields[k]
				if !ok {
					w.fail(path+"."+k, "fixture field has no %s field", typ)
					continue
				}
				w.seen[typ][typ.Field(idx).Name] = true
				w.compare(path+"."+k, v, got.Field(idx))
			}
		default:
			w.fail(path, "fixture is an object, Go is %s", got.Type())
		}
	case []any:
		if got.Kind() != reflect.Slice {
			w.fail(path, "fixture is an array, Go is %s", got.Type())
			return
		}
		if got.Len() != len(want) {
			w.fail(path, "Go has %d elements, fixture has %d", got.Len(), len(want))
			return
		}
		for i, v := range want {
			w.compare(fmt.Sprintf("%s[%d]", path, i), v, got.Index(i))
		}
	case string:
		switch {
		case got.Type().Implements(marshalerType):
			w.compareMarshaled(path, want, got)
		case got.Kind() == reflect.String:
			if got.String() != want {
				w.fail(path, "Go has %q, fixture has %q", got.String(), want)
			}
		case isUint(got.Kind()):
			n, err := strconv.ParseUint(want, 10, 64)
			if err != nil {
				w.fail(path, "fixture %q is not a decimal u64", want)
			} else if got.Uint() != n {
				w.fail(path, "Go has %d, fixture has %d", got.Uint(), n)
			}
		default:
			w.fail(path, "fixture is the string %q, Go is %s", want, got.Type())
		}
	case json.Number:
		switch {
		case isUint(got.Kind()):
			n, err := strconv.ParseUint(want.String(), 10, 64)
			if err != nil || got.Uint() != n {
				w.fail(path, "Go has %d, fixture has %s", got.Uint(), want)
			}
		case isInt(got.Kind()):
			n, err := strconv.ParseInt(want.String(), 10, 64)
			if err != nil || got.Int() != n {
				w.fail(path, "Go has %d, fixture has %s", got.Int(), want)
			}
		default:
			w.fail(path, "fixture is the number %s, Go is %s", want, got.Type())
		}
	case bool:
		if got.Kind() != reflect.Bool || got.Bool() != want {
			w.fail(path, "Go has %v, fixture has %v", got, want)
		}
	default:
		w.fail(path, "unexpected fixture value %T", want)
	}
}

func (w *goldenWalker) compareMarshaled(path string, want any, got reflect.Value) {
	w.t.Helper()
	encoded, err := json.Marshal(got.Interface())
	if err != nil {
		w.fail(path, "re-encoding %s: %v", got.Type(), err)
		return
	}
	var gotGeneric any
	dec := json.NewDecoder(bytes.NewReader(encoded))
	dec.UseNumber()
	if err := dec.Decode(&gotGeneric); err != nil {
		w.fail(path, "re-parsing %s: %v", got.Type(), err)
		return
	}
	if !reflect.DeepEqual(gotGeneric, want) {
		w.fail(path, "Go %s encodes to %s, fixture has %v", got.Type(), encoded, want)
	}
}

func isUint(k reflect.Kind) bool {
	switch k {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return true
	}
	return false
}

func isInt(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	}
	return false
}

func TestEventsGoldenDecodeEveryField(t *testing.T) {
	raw, parsed := goldenEvents(t)
	known := eventTypeConstants(t)

	all, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("re-encode fixture events: %v", err)
	}
	events, err := decodeEvents(all)
	if err != nil {
		t.Fatalf("decodeEvents: %v", err)
	}
	if len(events) != len(parsed) {
		t.Fatalf("decoded %d events, fixture has %d", len(events), len(parsed))
	}

	w := &goldenWalker{t: t, seen: map[reflect.Type]map[string]bool{}}
	fixtureTypes := map[string]bool{}
	for i, want := range parsed {
		typ, _ := want["type"].(string)
		fixtureTypes[typ] = true
		if _, ok := known[typ]; !ok {
			t.Errorf("events[%d]: fixture type %q has no EventType constant", i, typ)
		}
		w.compare(fmt.Sprintf("events[%d](%s)", i, typ), want, reflect.ValueOf(events[i]))

		if secret, ok := want["secret"]; ok && events[i].Secret != nil {
			w.compareMarshaled(fmt.Sprintf("events[%d](%s).secret re-encoded", i, typ), secret, reflect.ValueOf(*events[i].Secret))
		}
	}

	for value, name := range known {
		if !fixtureTypes[value] {
			t.Errorf("%s = %q has no sample in the fixture", name, value)
		}
	}

	for typ, seen := range w.seen {
		var unseen []string
		for i := 0; i < typ.NumField(); i++ {
			if name := typ.Field(i).Name; !seen[name] {
				unseen = append(unseen, name)
			}
		}
		sort.Strings(unseen)
		if len(unseen) > 0 {
			t.Errorf("%s fields never populated by the fixture: %v", typ, unseen)
		}
	}
}
