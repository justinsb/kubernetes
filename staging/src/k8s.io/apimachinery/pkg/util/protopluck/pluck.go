/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package protopluck extracts individual field values from a serialized
// protobuf message, addressed by field number, without decoding the rest of
// the message.
package protopluck

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
)

// Path addresses a field by the chain of protobuf field numbers leading to it
// from the root message. For example Path{1, 11} is metadata.labels on any
// Kubernetes API object: field 1 of the object, then field 11 of ObjectMeta.
type Path []int32

// Value is one occurrence of a plucked field on the wire.
type Value struct {
	// Index is the position of the matched Path in the arguments to Compile.
	Index int
	// Type is the wire type the field was encoded with.
	Type protowire.Type
	// Bytes is the payload of a length-delimited field (string, bytes,
	// embedded message, map entry). It aliases the plucked data.
	Bytes []byte
	// Num is the payload of a varint, fixed32 or fixed64 field.
	Num uint64
}

// Bool interprets a varint value as a bool.
func (v Value) Bool() bool { return v.Num != 0 }

// MapEntry interprets the value as an entry of a map whose keys and values are
// strings or bytes, which is how proto encodes map<string,string>: one
// embedded message per entry, with the key in field 1 and the value in field 2.
// The results alias the plucked data.
func (v Value) MapEntry() (key, value []byte, err error) {
	if v.Type != protowire.BytesType {
		return nil, nil, fmt.Errorf("map entry has wire type %d, expected length-delimited", v.Type)
	}
	b := v.Bytes
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, nil, protowire.ParseError(n)
		}
		b = b[n:]
		if typ == protowire.BytesType && (num == 1 || num == 2) {
			payload, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return nil, nil, protowire.ParseError(n)
			}
			if num == 1 {
				key = payload
			} else {
				value = payload
			}
			b = b[n:]
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return nil, nil, protowire.ParseError(n)
		}
		b = b[n:]
	}
	return key, value, nil
}

// Plucker extracts a fixed set of fields. The set is fixed up front so that a
// single pass over the message is enough, however many fields are wanted.
// A Plucker is immutable and safe for concurrent use.
type Plucker struct {
	root node
}

type node struct {
	edges []edge
}

type edge struct {
	num protowire.Number
	// leaf is the index of the path ending here, or -1.
	leaf int
	// child is non-nil if longer paths continue through this field.
	child *node
}

func (n *node) find(num protowire.Number) *edge {
	// Linear scan: callers ask for a handful of fields per message.
	for i := range n.edges {
		if n.edges[i].num == num {
			return &n.edges[i]
		}
	}
	return nil
}

// Compile builds a Plucker for the given paths. A path may not be empty,
// repeated, or a prefix of another path.
func Compile(paths ...Path) (*Plucker, error) {
	p := &Plucker{}
	for i, path := range paths {
		if len(path) == 0 {
			return nil, fmt.Errorf("path %d is empty", i)
		}
		n := &p.root
		for depth, num := range path {
			if num <= 0 || protowire.Number(num) > protowire.MaxValidNumber {
				return nil, fmt.Errorf("path %d (%v) has invalid field number %d", i, path, num)
			}
			e := n.find(protowire.Number(num))
			if e == nil {
				n.edges = append(n.edges, edge{num: protowire.Number(num), leaf: -1})
				e = &n.edges[len(n.edges)-1]
			}
			last := depth == len(path)-1
			switch {
			case e.leaf >= 0:
				return nil, fmt.Errorf("path %d (%v) duplicates or extends path %d (%v)", i, path, e.leaf, paths[e.leaf])
			case last && e.child != nil:
				return nil, fmt.Errorf("path %d (%v) is a prefix of another path", i, path)
			case last:
				e.leaf = i
			default:
				if e.child == nil {
					e.child = &node{}
				}
				n = e.child
			}
		}
	}
	return p, nil
}

// MustCompile is like Compile but panics on error.
func MustCompile(paths ...Path) *Plucker {
	p, err := Compile(paths...)
	if err != nil {
		panic(err)
	}
	return p
}

var errNotMessage = errors.New("field on the path to a plucked value is not length-delimited")

// Pluck appends to dst every occurrence of the compiled paths in data, in wire
// order, and returns the extended slice. Fields that are not on a compiled
// path are skipped without being interpreted.
//
// Wire order is what lets callers apply protobuf merge semantics themselves:
// for a singular field the last Value wins, for a repeated field (or map)
// every Value is an element. A message that was split across several
// occurrences on the wire is handled by recursing into each of them.
//
// Returned values alias data.
func (p *Plucker) Pluck(data []byte, dst []Value) ([]Value, error) {
	return p.root.pluck(data, dst)
}

func (n *node) pluck(b []byte, dst []Value) ([]Value, error) {
	for len(b) > 0 {
		num, typ, tagLen := protowire.ConsumeTag(b)
		if tagLen < 0 {
			return dst, protowire.ParseError(tagLen)
		}
		b = b[tagLen:]

		e := n.find(num)
		if e == nil {
			skip := protowire.ConsumeFieldValue(num, typ, b)
			if skip < 0 {
				return dst, protowire.ParseError(skip)
			}
			b = b[skip:]
			continue
		}

		var v Value
		var valLen int
		switch typ {
		case protowire.BytesType:
			v.Bytes, valLen = protowire.ConsumeBytes(b)
		case protowire.VarintType:
			v.Num, valLen = protowire.ConsumeVarint(b)
		case protowire.Fixed64Type:
			v.Num, valLen = protowire.ConsumeFixed64(b)
		case protowire.Fixed32Type:
			var n32 uint32
			n32, valLen = protowire.ConsumeFixed32(b)
			v.Num = uint64(n32)
		default:
			return dst, fmt.Errorf("field %d has unsupported wire type %d", num, typ)
		}
		if valLen < 0 {
			return dst, protowire.ParseError(valLen)
		}
		b = b[valLen:]

		if e.child != nil {
			if typ != protowire.BytesType {
				return dst, fmt.Errorf("field %d: %w", num, errNotMessage)
			}
			var err error
			if dst, err = e.child.pluck(v.Bytes, dst); err != nil {
				return dst, err
			}
			continue
		}
		v.Index = e.leaf
		v.Type = typ
		dst = append(dst, v)
	}
	return dst, nil
}

// Range calls fn for every field of the message in data, in wire order, with
// the field's number and its value (Value.Index is not meaningful here). It
// stops and returns false if fn does, or if data is not a well-formed message.
//
// It is the building block for checks a list of paths cannot express, such as
// "every element of this repeated message has that field set".
func Range(data []byte, fn func(num int32, v Value) bool) bool {
	for len(data) > 0 {
		num, typ, tagLen := protowire.ConsumeTag(data)
		if tagLen < 0 {
			return false
		}
		data = data[tagLen:]
		v := Value{Type: typ}
		var valLen int
		switch typ {
		case protowire.BytesType:
			v.Bytes, valLen = protowire.ConsumeBytes(data)
		case protowire.VarintType:
			v.Num, valLen = protowire.ConsumeVarint(data)
		case protowire.Fixed64Type:
			v.Num, valLen = protowire.ConsumeFixed64(data)
		case protowire.Fixed32Type:
			var n32 uint32
			n32, valLen = protowire.ConsumeFixed32(data)
			v.Num = uint64(n32)
		default:
			return false
		}
		if valLen < 0 {
			return false
		}
		data = data[valLen:]
		if !fn(int32(num), v) {
			return false
		}
	}
	return true
}
