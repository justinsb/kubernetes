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

package rawobject

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
	"k8s.io/apimachinery/pkg/util/protopluck"
)

// The tests use PartialObjectMetadata as their API type: it has ObjectMeta
// where every object has it, and is at hand without importing an API group.
var testGVK = schema.GroupVersionKind{Group: "example.io", Version: "v1", Kind: "Thing"}

var testPlucker = protopluck.MustCompile(NamePath, NamespacePath, LabelsPath)

func testAttrs(msg []byte) (Attrs, error) {
	values, err := testPlucker.Pluck(msg, nil)
	if err != nil {
		return Attrs{}, err
	}
	var meta ObjectMetaAttrs
	for _, v := range values {
		switch v.Index {
		case 0:
			meta.SetName(v)
		case 1:
			meta.SetNamespace(v)
		case 2:
			if err := meta.AddLabel(v); err != nil {
				return Attrs{}, err
			}
		}
	}
	return meta.Attrs(), nil
}

func testDecode(value []byte, rev int64) (runtime.Object, error) {
	unk := &runtime.Unknown{}
	if err := unk.Unmarshal(value[len(protoMagic):]); err != nil {
		return nil, err
	}
	obj := &metav1.PartialObjectMetadata{}
	if err := obj.Unmarshal(unk.Raw); err != nil {
		return nil, err
	}
	obj.ResourceVersion = formatResourceVersion(rev)
	return obj, nil
}

func testFactory() *Factory {
	return NewFactory(Config{GroupVersionKind: testGVK, AttrFunc: testAttrs}, testDecode)
}

// envelope wraps msg the way the protobuf serializer does before it goes to storage.
func envelope(t *testing.T, gvk schema.GroupVersionKind, msg []byte) []byte {
	t.Helper()
	unk := runtime.Unknown{TypeMeta: runtime.TypeMeta{APIVersion: gvk.GroupVersion().String(), Kind: gvk.Kind}, Raw: msg}
	data, err := unk.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return append(append([]byte{}, protoMagic...), data...)
}

func marshal(t *testing.T, obj *metav1.PartialObjectMetadata) []byte {
	t.Helper()
	data, err := obj.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestSpliceMatchesMarshal checks that injecting a resourceVersion yields the
// bytes that decoding, setting it and encoding would. Names of every length
// take the length prefix of metadata across its size boundaries.
func TestSpliceMatchesMarshal(t *testing.T) {
	for _, stored := range []string{"", "5"} {
		for _, rev := range []int64{0, 9, 1234567890123} {
			for nameLen := 0; nameLen < 300; nameLen++ {
				obj := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
					Name:            strings.Repeat("n", nameLen),
					ResourceVersion: stored,
					Labels:          map[string]string{"k": "v"},
				}}
				raw, ok := testFactory().New(envelope(t, testGVK, marshal(t, obj)), rev)
				if !ok {
					t.Fatalf("name of %d bytes: object was not kept serialized", nameLen)
				}
				obj.ResourceVersion = formatResourceVersion(rev)
				want := marshal(t, obj)
				got := make([]byte, raw.Size())
				n, err := raw.MarshalTo(got)
				if err != nil {
					t.Fatal(err)
				}
				if n != len(want) || !bytes.Equal(got, want) {
					t.Fatalf("name of %d bytes, stored resourceVersion %q, revision %d:\n got %x\nwant %x", nameLen, stored, rev, got, want)
				}
			}
		}
	}
}

// TestSpliceWithoutResourceVersion covers encodings the generated marshalers
// never write but other writers may: ones with no resourceVersion field.
func TestSpliceWithoutResourceVersion(t *testing.T) {
	field := func(num protowire.Number, value string) []byte {
		return protowire.AppendString(protowire.AppendTag(nil, num, protowire.BytesType), value)
	}
	object := func(metadata ...[]byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(nil, metadataField, protowire.BytesType), bytes.Join(metadata, nil))
	}
	rv := field(resourceVersionField, "7")
	for name, tc := range map[string]struct{ msg, want []byte }{
		"empty metadata":  {msg: object(), want: object(rv)},
		"lower fields":    {msg: object(field(1, "name"), field(3, "ns")), want: object(field(1, "name"), field(3, "ns"), rv)},
		"higher fields":   {msg: object(field(12, "a"), field(14, "f")), want: object(rv, field(12, "a"), field(14, "f"))},
		"in the middle":   {msg: object(field(1, "name"), field(14, "f")), want: object(field(1, "name"), rv, field(14, "f"))},
		"after metadata":  {msg: append(object(field(1, "name")), field(2, "spec")...), want: append(object(field(1, "name"), rv), field(2, "spec")...)},
		"before metadata": {msg: append(field(2, "spec"), object(field(1, "name"))...), want: append(field(2, "spec"), object(field(1, "name"), rv)...)},
	} {
		t.Run(name, func(t *testing.T) {
			raw, ok := testFactory().New(envelope(t, testGVK, tc.msg), 7)
			if !ok {
				t.Fatal("object was not kept serialized")
			}
			got := make([]byte, raw.Size())
			if _, err := raw.MarshalTo(got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("\n got %x\nwant %x", got, tc.want)
			}
		})
	}
}

// TestNewFallsBack lists what is left to the regular decoder.
func TestNewFallsBack(t *testing.T) {
	msg := marshal(t, &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "name"}})
	metadata := msg // the object consists of its metadata field only
	rv := protowire.AppendString(protowire.AppendTag(nil, resourceVersionField, protowire.BytesType), "1")

	otherKind, otherVersion := testGVK, testGVK
	otherKind.Kind, otherVersion.Version = "Other", "v2"
	gzipped, err := (&runtime.Unknown{TypeMeta: runtime.TypeMeta{APIVersion: "example.io/v1", Kind: "Thing"}, Raw: msg, ContentEncoding: "gzip"}).Marshal()
	if err != nil {
		t.Fatal(err)
	}

	for name, value := range map[string][]byte{
		"json":                      []byte(`{"apiVersion":"example.io/v1","kind":"Thing","metadata":{"name":"name"}}`),
		"empty":                     nil,
		"another kind":              envelope(t, otherKind, msg),
		"another version":           envelope(t, otherVersion, msg),
		"content encoding":          append(append([]byte{}, protoMagic...), gzipped...),
		"no metadata":               envelope(t, testGVK, nil),
		"metadata twice":            envelope(t, testGVK, append(append([]byte{}, metadata...), metadata...)),
		"resourceVersion twice":     envelope(t, testGVK, protowire.AppendBytes(protowire.AppendTag(nil, metadataField, protowire.BytesType), append(append([]byte{}, rv...), rv...))),
		"truncated":                 envelope(t, testGVK, msg[:len(msg)-1]),
		"metadata is not a message": envelope(t, testGVK, protowire.AppendVarint(protowire.AppendTag(nil, metadataField, protowire.VarintType), 1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := testFactory().New(value, 1); ok {
				t.Errorf("value was kept serialized")
			}
		})
	}

	if _, ok := testFactory().New(envelope(t, testGVK, msg), 1); !ok {
		t.Errorf("the well-formed value the cases above derive from was not kept serialized")
	}
}

func TestObject(t *testing.T) {
	stored := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
		Name:        "name",
		Namespace:   "ns",
		UID:         "uid",
		Labels:      map[string]string{"k": "v"},
		Annotations: map[string]string{"a": "b"},
	}}
	decodes := 0
	factory := NewFactory(Config{GroupVersionKind: testGVK, AttrFunc: testAttrs}, func(value []byte, rev int64) (runtime.Object, error) {
		decodes++
		return testDecode(value, rev)
	})
	raw, ok := factory.New(envelope(t, testGVK, marshal(t, stored)), 10)
	if !ok {
		t.Fatal("object was not kept serialized")
	}
	protoID := protobuf.NewSerializer(nil, nil).Identifier()

	// What routing an event needs is available without decoding.
	if raw.GetName() != "name" || raw.GetNamespace() != "ns" || raw.GetResourceVersion() != "10" || !reflect.DeepEqual(raw.GetLabels(), map[string]string{"k": "v"}) {
		t.Errorf("unexpected plucked metadata: %s/%s@%s %v", raw.GetNamespace(), raw.GetName(), raw.GetResourceVersion(), raw.GetLabels())
	}
	if gvk := raw.GetObjectKind().GroupVersionKind(); gvk != testGVK {
		t.Errorf("unexpected kind %v", gvk)
	}
	if !raw.EncodableBy(protoID) || raw.EncodableBy("json") {
		t.Errorf("object should be encodable as is by the protobuf serializer and by it only")
	}
	if decodes != 0 {
		t.Fatalf("object was decoded %d times before anything required it", decodes)
	}

	// The resourceVersion belongs to the copy, everything else is shared.
	deleted := raw.DeepCopyObject().(*Object)
	deleted.SetResourceVersion("11")
	if raw.GetResourceVersion() != "10" || deleted.GetResourceVersion() != "11" {
		t.Errorf("resourceVersions: original %s, copy %s", raw.GetResourceVersion(), deleted.GetResourceVersion())
	}
	if !deleted.EncodableBy(protoID) || decodes != 0 {
		t.Errorf("changing the resourceVersion should not cost the serialized form")
	}

	// Anything else decodes, once, however many copies ask.
	if raw.GetUID() != "uid" || deleted.GetAnnotations()["a"] != "b" {
		t.Errorf("unexpected decoded metadata")
	}
	for _, o := range []*Object{raw, deleted} {
		decoded, err := Decoded(o)
		if err != nil {
			t.Fatal(err)
		}
		want := stored.DeepCopy()
		want.ResourceVersion = o.GetResourceVersion()
		if !reflect.DeepEqual(decoded, want) {
			t.Errorf("decoded %#v, want %#v", decoded, want)
		}
	}
	if decodes != 1 {
		t.Errorf("object was decoded %d times, expected once", decodes)
	}

	// Mutating a copy beyond its resourceVersion makes it an ordinary object
	// that has to be encoded the ordinary way, and leaves the original alone.
	mutated := raw.DeepCopyObject().(*Object)
	mutated.SetLabels(map[string]string{"k": "changed"})
	mutated.SetResourceVersion("12")
	if mutated.EncodableBy(protoID) {
		t.Errorf("mutated object still claims its stored bytes are current")
	}
	if _, err := mutated.MarshalTo(make([]byte, 1024)); err == nil {
		t.Errorf("mutated object still writes its stored bytes")
	}
	decoded, err := mutated.DecodedObject()
	if err != nil {
		t.Fatal(err)
	}
	if m := decoded.(*metav1.PartialObjectMetadata); m.Labels["k"] != "changed" || m.ResourceVersion != "12" || mutated.GetLabels()["k"] != "changed" || mutated.Attrs().Labels["k"] != "changed" {
		t.Errorf("mutation is not reflected: %#v", m)
	}
	if raw.GetLabels()["k"] != "v" || !raw.EncodableBy(protoID) {
		t.Errorf("mutating a copy affected the original")
	}
	if again := mutated.DeepCopyObject().(*Object); again.GetLabels()["k"] != "changed" || again.EncodableBy(protoID) {
		t.Errorf("copy of a mutated object lost the mutation")
	}

	if obj := runtime.Object(stored); mustDecoded(t, obj) != obj {
		t.Errorf("Decoded should return ordinary objects as they are")
	}
}

func mustDecoded(t *testing.T, obj runtime.Object) runtime.Object {
	t.Helper()
	decoded, err := Decoded(obj)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestDecodeError(t *testing.T) {
	factory := NewFactory(Config{GroupVersionKind: testGVK, AttrFunc: testAttrs}, func([]byte, int64) (runtime.Object, error) {
		return nil, fmt.Errorf("boom")
	})
	raw, ok := factory.New(envelope(t, testGVK, marshal(t, &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "name"}})), 1)
	if !ok {
		t.Fatal("object was not kept serialized")
	}
	if _, err := raw.DecodedObject(); err == nil {
		t.Errorf("expected the decode error")
	}
	// Getters have no way to report it, and must not blow up.
	if raw.GetUID() != "" || raw.GetName() != "name" {
		t.Errorf("unexpected metadata from an object that cannot be decoded")
	}
}
