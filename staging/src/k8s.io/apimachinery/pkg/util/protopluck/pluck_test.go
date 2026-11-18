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

package protopluck

import (
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Field numbers of metav1.PartialObjectMetadata, ObjectMeta and OwnerReference.
const (
	pathName = iota
	pathGeneration
	pathLabels
	pathOwnerUID
)

var testPlucker = MustCompile(
	Path{1, 1},
	Path{1, 7},
	Path{1, 11},
	Path{1, 13, 4},
)

type plucked struct {
	name       string
	generation int64
	labels     map[string]string
	ownerUIDs  []string
}

func pluck(t *testing.T, data []byte) plucked {
	t.Helper()
	values, err := testPlucker.Pluck(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	var p plucked
	for _, v := range values {
		switch v.Index {
		case pathName:
			p.name = string(v.Bytes)
		case pathGeneration:
			p.generation = int64(v.Num)
		case pathLabels:
			key, value, err := v.MapEntry()
			if err != nil {
				t.Fatal(err)
			}
			if p.labels == nil {
				p.labels = map[string]string{}
			}
			p.labels[string(key)] = string(value)
		case pathOwnerUID:
			p.ownerUIDs = append(p.ownerUIDs, string(v.Bytes))
		}
	}
	return p
}

func testObject() *metav1.PartialObjectMetadata {
	return &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
		Name:        "name",
		Namespace:   "namespace",
		Generation:  7,
		Labels:      map[string]string{"a": "1", "b": "", "": "empty-key"},
		Annotations: map[string]string{"a": "not a label"},
		OwnerReferences: []metav1.OwnerReference{
			{Kind: "A", Name: "a", UID: types.UID("uid-a")},
			{Kind: "B", Name: "b", UID: types.UID("uid-b")},
		},
		ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "m", FieldsV1: &metav1.FieldsV1{}}},
	}}
}

func TestPluck(t *testing.T) {
	obj := testObject()
	data, err := obj.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := plucked{
		name:       "name",
		generation: 7,
		labels:     map[string]string{"a": "1", "b": "", "": "empty-key"},
		ownerUIDs:  []string{"uid-a", "uid-b"},
	}
	if got := pluck(t, data); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}

	t.Run("nothing to find", func(t *testing.T) {
		if got := pluck(t, nil); !reflect.DeepEqual(got, plucked{}) {
			t.Errorf("got %+v from empty message", got)
		}
	})

	// Protobuf lets a message be split in several chunks, to be merged by the
	// reader. Later scalars win, repeated fields accumulate.
	t.Run("split message", func(t *testing.T) {
		more := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
			Name:            "renamed",
			Labels:          map[string]string{"a": "2", "c": "3"},
			OwnerReferences: []metav1.OwnerReference{{UID: types.UID("uid-c")}},
		}}
		moreData, err := more.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		want := plucked{
			name:       "renamed",
			generation: 0, // the generated marshaler writes zero values, so the second chunk overrides it
			labels:     map[string]string{"a": "2", "b": "", "": "empty-key", "c": "3"},
			ownerUIDs:  []string{"uid-a", "uid-b", "uid-c"},
		}
		if got := pluck(t, append(append([]byte{}, data...), moreData...)); !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	// Fields that are not asked for are skipped whatever they are, including
	// ones the schema does not know about.
	t.Run("unknown fields", func(t *testing.T) {
		var b []byte
		b = protowire.AppendTag(b, 100, protowire.StartGroupType)
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendString(b, "inside a group")
		b = protowire.AppendTag(b, 100, protowire.EndGroupType)
		b = protowire.AppendTag(b, 101, protowire.Fixed32Type)
		b = protowire.AppendFixed32(b, 1)
		b = protowire.AppendTag(b, 102, protowire.Fixed64Type)
		b = protowire.AppendFixed64(b, 1)
		b = append(b, data...)
		b = protowire.AppendTag(b, 103, protowire.VarintType)
		b = protowire.AppendVarint(b, 1)
		if got := pluck(t, b); !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("does not allocate", func(t *testing.T) {
		var buf [16]Value
		allocs := testing.AllocsPerRun(100, func() {
			if _, err := testPlucker.Pluck(data, buf[:0]); err != nil {
				t.Fatal(err)
			}
		})
		if allocs != 0 {
			t.Errorf("%v allocations per Pluck", allocs)
		}
	})
}

func TestPluckErrors(t *testing.T) {
	data, err := testObject().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// Every truncation either still parses, when it happens to fall on a
	// field boundary, or fails. It never panics.
	failures := 0
	for i := range data {
		if _, err := testPlucker.Pluck(data[:i], nil); err != nil {
			failures++
		}
	}
	if failures == 0 {
		t.Errorf("no truncation of the message was rejected")
	}

	// metadata as a varint: there is nothing to descend into.
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, 1)
	if _, err := testPlucker.Pluck(b, nil); err == nil {
		t.Errorf("expected an error for a scalar where a message is expected")
	}
}

func TestCompile(t *testing.T) {
	for name, tc := range map[string]struct {
		paths []Path
		err   string
	}{
		"ok":             {paths: []Path{{1}, {2, 1}, {2, 2}, {3, 1, 1}}},
		"empty path":     {paths: []Path{{}}, err: "empty"},
		"zero field":     {paths: []Path{{1, 0}}, err: "invalid field number"},
		"negative field": {paths: []Path{{-1}}, err: "invalid field number"},
		"duplicate":      {paths: []Path{{1, 2}, {1, 2}}, err: "duplicates or extends"},
		"extends":        {paths: []Path{{1}, {1, 2}}, err: "duplicates or extends"},
		"prefix":         {paths: []Path{{1, 2}, {1}}, err: "prefix of another"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Compile(tc.paths...)
			switch {
			case tc.err == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
				t.Errorf("expected error containing %q, got %v", tc.err, err)
			}
		})
	}
}

func TestRange(t *testing.T) {
	obj := testObject()
	data, err := obj.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// One level at a time: the object holds metadata, which holds the rest.
	var metadata []byte
	if !Range(data, func(num int32, v Value) bool {
		if num == 1 {
			metadata = v.Bytes
		}
		return true
	}) {
		t.Fatal("well-formed message was rejected")
	}
	var name string
	var generation int64
	owners := 0
	if !Range(metadata, func(num int32, v Value) bool {
		switch num {
		case 1:
			name = string(v.Bytes)
		case 7:
			generation = int64(v.Num)
		case 13:
			owners++
		}
		return true
	}) {
		t.Fatal("well-formed message was rejected")
	}
	if name != obj.Name || generation != obj.Generation || owners != len(obj.OwnerReferences) {
		t.Errorf("got name %q, generation %d, %d owners", name, generation, owners)
	}

	visited := 0
	if Range(metadata, func(int32, Value) bool { visited++; return false }) || visited != 1 {
		t.Errorf("expected Range to stop and report it when told to, visited %d fields", visited)
	}
	if Range(metadata[:len(metadata)-1], func(int32, Value) bool { return true }) {
		t.Errorf("truncated message was accepted")
	}
}
