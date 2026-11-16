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

// Package rawobject lets objects read from storage stay in their serialized
// protobuf form all the way to a protobuf watch response.
//
// The usual path decodes each stored object, converts it to the internal
// version, converts it back and encodes it again, only to produce bytes that
// differ from the stored ones in a single field: metadata.resourceVersion.
// An Object instead keeps the stored bytes, plucks out the few values the
// apiserver needs to route and filter the event, and splices the
// resourceVersion in while writing the response. It decodes itself the first
// time something asks for more than that.
//
// What this gives up, compared to decoding:
//
//   - Protobuf watchers receive objects as they were written. Defaults
//     introduced after an object was last written are not applied to it, and
//     neither are conversion changes. JSON watchers, and anything reading
//     through GET or LIST, still see them, because they get the decoded object.
//   - A value that cannot be decoded is not noticed until something decodes it.
//   - An object that is both watched and read is held in both forms.
//
// Values that are not protobuf, or not of the configured type, are left to the
// regular decoder, so stores can hold a mix.
package rawobject

import (
	"bytes"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/protopluck"
)

// Attrs are the values plucked out of a serialized object: enough to key it,
// index it and evaluate label and field selectors against it.
type Attrs struct {
	Name      string
	Namespace string
	Labels    labels.Set
	Fields    fields.Set
}

// Config describes which stored objects can be kept serialized.
type Config struct {
	// GroupVersionKind is the only type kept serialized. It has to be both
	// what is written to storage and what is served to clients, otherwise
	// there is a conversion to do and so a decode to pay for.
	GroupVersionKind schema.GroupVersionKind
	// AttrFunc plucks Attrs from the protobuf encoding of an object of that
	// type. It must agree with the storage.AttrFunc used for decoded objects.
	AttrFunc func(msg []byte) (Attrs, error)
}

// DecodeFunc fully decodes a value read from storage at the given revision.
type DecodeFunc func(value []byte, rev int64) (runtime.Object, error)

// Factory builds Objects out of values read from storage.
type Factory struct {
	config     Config
	kind       fixedKind
	apiVersion []byte
	kindName   []byte
	decode     DecodeFunc
}

// NewFactory returns a Factory. decode is what Objects fall back to when
// their decoded form is needed after all.
func NewFactory(config Config, decode DecodeFunc) *Factory {
	return &Factory{
		config:     config,
		kind:       fixedKind(config.GroupVersionKind),
		apiVersion: []byte(config.GroupVersionKind.GroupVersion().String()),
		kindName:   []byte(config.GroupVersionKind.Kind),
		decode:     decode,
	}
}

// Stats counts what happened to Objects process-wide. It exists so that tests
// and benchmarks can tell whether decoding was actually avoided.
type Stats struct {
	// Created is the number of values kept serialized.
	Created uint64
	// Decoded is the number of Objects that ended up decoded anyway.
	Decoded uint64
	// PassedThrough is the number of times stored bytes were written to an encoder.
	PassedThrough uint64
}

var created, decoded, passedThrough atomic.Uint64

// ReadStats returns the current counters.
func ReadStats() Stats {
	return Stats{Created: created.Load(), Decoded: decoded.Load(), PassedThrough: passedThrough.Load()}
}

// protoMagic prefixes every protobuf-encoded value in storage. It is followed
// by a runtime.Unknown wrapping the object.
var protoMagic = []byte{0x6b, 0x38, 0x73, 0x00}

const (
	envelopeAPIVersion = iota
	envelopeKind
	envelopeRaw
	envelopeContentEncoding
	envelopeContentType
)

// envelopePlucker reads runtime.Unknown.
var envelopePlucker = protopluck.MustCompile(
	protopluck.Path{1, 1},
	protopluck.Path{1, 2},
	protopluck.Path{2},
	protopluck.Path{3},
	protopluck.Path{4},
)

// New returns value as an Object, or false if it has to go through a regular
// decode: because it is not protobuf, not the expected type, or laid out in a
// way this package does not want to deal with. value is retained.
func (f *Factory) New(value []byte, rev int64) (*Object, bool) {
	if !bytes.HasPrefix(value, protoMagic) {
		return nil, false
	}
	var buf [8]protopluck.Value
	envelope, err := envelopePlucker.Pluck(value[len(protoMagic):], buf[:0])
	if err != nil {
		return nil, false
	}
	var msg []byte
	var sawAPIVersion, sawKind, sawRaw bool
	for _, v := range envelope {
		switch v.Index {
		case envelopeAPIVersion:
			sawAPIVersion = bytes.Equal(v.Bytes, f.apiVersion)
		case envelopeKind:
			sawKind = bytes.Equal(v.Bytes, f.kindName)
		case envelopeRaw:
			if sawRaw {
				return nil, false
			}
			sawRaw, msg = true, v.Bytes
		case envelopeContentEncoding:
			if len(v.Bytes) != 0 {
				return nil, false
			}
		case envelopeContentType:
			if len(v.Bytes) != 0 && string(v.Bytes) != runtime.ContentTypeProtobuf {
				return nil, false
			}
		}
	}
	if !sawAPIVersion || !sawKind || !sawRaw {
		return nil, false
	}

	sp, err := findSplice(msg)
	if err != nil {
		return nil, false
	}
	attrs, err := f.config.AttrFunc(msg)
	if err != nil {
		return nil, false
	}
	created.Add(1)
	rv := formatResourceVersion(rev)
	return &Object{
		rv: rv,
		stored: &stored{
			factory: f,
			value:   value,
			rev:     rev,
			rv:      rv,
			msg:     msg,
			splice:  sp,
			attrs:   attrs,
		},
	}, true
}

func formatResourceVersion(rev int64) string {
	if rev == 0 {
		return ""
	}
	return strconv.FormatUint(uint64(rev), 10)
}

// stored is the immutable part of an Object, shared between its copies.
type stored struct {
	factory *Factory
	// value is what was read from storage, envelope included.
	value []byte
	rev   int64
	rv    string
	// msg is the serialized object within value.
	msg    []byte
	splice splice
	attrs  Attrs

	decodeOnce sync.Once
	decoded    metaObject
	decodeErr  error
}

type metaObject interface {
	runtime.Object
	metav1.Object
}

func (s *stored) decode() (metaObject, error) {
	s.decodeOnce.Do(func() {
		decoded.Add(1)
		obj, err := s.factory.decode(s.value, s.rev)
		if err != nil {
			s.decodeErr = err
			return
		}
		m, ok := obj.(metaObject)
		if !ok {
			s.decodeErr = fmt.Errorf("decoded object %T does not implement metav1.Object", obj)
			return
		}
		s.decoded = m
	})
	return s.decoded, s.decodeErr
}

// Object is an API object held as the bytes it was stored as.
//
// It implements metav1.Object so that it can stand in for the decoded object
// wherever only metadata is consulted. Name, namespace, labels and
// resourceVersion are served from plucked values; any other getter decodes.
// Setting the resourceVersion is free. Any other setter turns the Object into
// a plain wrapper around a decoded copy, and gives up on passing the stored
// bytes through.
//
// An Object is not safe for concurrent mutation, like any other API object.
// Copies are cheap and share the stored bytes.
//
// NOTE: the protobuf serializer probes structs with exactly three fields for
// being a list, and its reflection panics on unexported fields. Keep this
// struct at any other field count, or teach the serializer about it.
type Object struct {
	stored *stored
	// rv is the resourceVersion this copy reports and encodes.
	rv string
	// mutated, once set, is the source of truth instead of stored.
	mutated metaObject
	// keep the field count away from three, see above.
	_ struct{}
}

var (
	_ runtime.SerializedObject   = &Object{}
	_ metav1.Object              = &Object{}
	_ runtime.ProtobufMarshaller = &Object{}
)

// protobufIdentifier is how the protobuf serializer identifies itself.
var protobufIdentifier = protobuf.NewSerializer(nil, nil).Identifier()

// Attrs returns the values plucked from the serialized object. The maps are
// shared and must not be mutated.
func (o *Object) Attrs() Attrs {
	if o.mutated != nil {
		// Whoever mutated the object wants the decoded path, and gets it.
		attrs := o.stored.attrs
		attrs.Name, attrs.Namespace, attrs.Labels = o.mutated.GetName(), o.mutated.GetNamespace(), o.mutated.GetLabels()
		return attrs
	}
	return o.stored.attrs
}

// GetObjectKind implements runtime.Object.
func (o *Object) GetObjectKind() schema.ObjectKind {
	if o.mutated != nil {
		return o.mutated.GetObjectKind()
	}
	return &o.stored.factory.kind
}

// fixedKind is the kind of something already serialized: it is what it is.
type fixedKind schema.GroupVersionKind

func (k *fixedKind) SetGroupVersionKind(schema.GroupVersionKind) {}
func (k *fixedKind) GroupVersionKind() schema.GroupVersionKind   { return schema.GroupVersionKind(*k) }

// DeepCopyObject implements runtime.Object. The stored bytes are immutable
// and shared rather than copied.
func (o *Object) DeepCopyObject() runtime.Object {
	c := &Object{stored: o.stored, rv: o.rv}
	if o.mutated != nil {
		c.mutated = o.mutated.DeepCopyObject().(metaObject)
	}
	return c
}

// EncodableBy implements runtime.SerializedObject.
func (o *Object) EncodableBy(encoder runtime.Identifier) bool {
	return o.mutated == nil && encoder == protobufIdentifier
}

// DecodedObject implements runtime.SerializedObject.
func (o *Object) DecodedObject() (runtime.Object, error) {
	if o.mutated != nil {
		return o.mutated, nil
	}
	decoded, err := o.stored.decode()
	if err != nil {
		return nil, err
	}
	if o.rv == o.stored.rv {
		return decoded, nil
	}
	// Only delete events carry a resourceVersion other than the one the
	// object was stored at, so this copy is not worth caching.
	c := decoded.DeepCopyObject().(metaObject)
	c.SetResourceVersion(o.rv)
	return c, nil
}

// Size implements the protobuf sizer the serializer looks for.
func (o *Object) Size() int {
	return o.stored.splice.size(len(o.stored.msg), o.rv)
}

// MarshalTo implements runtime.ProtobufMarshaller by writing the stored bytes
// with the resourceVersion spliced in.
func (o *Object) MarshalTo(data []byte) (int, error) {
	if o.mutated != nil {
		return 0, fmt.Errorf("rawobject: object was mutated and can no longer be written from its stored bytes")
	}
	size := o.Size()
	if len(data) < size {
		return 0, fmt.Errorf("rawobject: buffer of %d bytes is too small for %d", len(data), size)
	}
	out := o.stored.splice.appendTo(data[:0], o.stored.msg, o.rv)
	if len(out) != size {
		return 0, fmt.Errorf("rawobject: wrote %d bytes, expected %d", len(out), size)
	}
	passedThrough.Add(1)
	return size, nil
}

// decodedMeta backs the getters that have no plucked value to return.
func (o *Object) decodedMeta() metav1.Object {
	if o.mutated != nil {
		return o.mutated
	}
	decoded, err := o.stored.decode()
	if err != nil {
		// The getters cannot fail. Callers that care about decode errors
		// see them from DecodedObject; here an empty object is all there is.
		return &metav1.ObjectMeta{}
	}
	return decoded
}

// mutableMeta backs the setters that cannot be expressed as a splice.
func (o *Object) mutableMeta() metav1.Object {
	if o.mutated == nil {
		if decoded, err := o.DecodedObject(); err == nil {
			o.mutated = decoded.DeepCopyObject().(metaObject)
		} else {
			return &metav1.ObjectMeta{}
		}
	}
	return o.mutated
}

func (o *Object) GetName() string {
	if o.mutated != nil {
		return o.mutated.GetName()
	}
	return o.stored.attrs.Name
}

func (o *Object) GetNamespace() string {
	if o.mutated != nil {
		return o.mutated.GetNamespace()
	}
	return o.stored.attrs.Namespace
}

func (o *Object) GetLabels() map[string]string {
	if o.mutated != nil {
		return o.mutated.GetLabels()
	}
	return o.stored.attrs.Labels
}

func (o *Object) GetResourceVersion() string {
	if o.mutated != nil {
		return o.mutated.GetResourceVersion()
	}
	return o.rv
}

func (o *Object) SetResourceVersion(version string) {
	if o.mutated != nil {
		o.mutated.SetResourceVersion(version)
		return
	}
	o.rv = version
}

func (o *Object) GetGenerateName() string           { return o.decodedMeta().GetGenerateName() }
func (o *Object) GetUID() types.UID                 { return o.decodedMeta().GetUID() }
func (o *Object) GetGeneration() int64              { return o.decodedMeta().GetGeneration() }
func (o *Object) GetSelfLink() string               { return o.decodedMeta().GetSelfLink() }
func (o *Object) GetFinalizers() []string           { return o.decodedMeta().GetFinalizers() }
func (o *Object) GetAnnotations() map[string]string { return o.decodedMeta().GetAnnotations() }
func (o *Object) GetCreationTimestamp() metav1.Time {
	return o.decodedMeta().GetCreationTimestamp()
}
func (o *Object) GetDeletionTimestamp() *metav1.Time {
	return o.decodedMeta().GetDeletionTimestamp()
}
func (o *Object) GetDeletionGracePeriodSeconds() *int64 {
	return o.decodedMeta().GetDeletionGracePeriodSeconds()
}
func (o *Object) GetOwnerReferences() []metav1.OwnerReference {
	return o.decodedMeta().GetOwnerReferences()
}
func (o *Object) GetManagedFields() []metav1.ManagedFieldsEntry {
	return o.decodedMeta().GetManagedFields()
}

func (o *Object) SetName(name string)                 { o.mutableMeta().SetName(name) }
func (o *Object) SetNamespace(namespace string)       { o.mutableMeta().SetNamespace(namespace) }
func (o *Object) SetGenerateName(name string)         { o.mutableMeta().SetGenerateName(name) }
func (o *Object) SetUID(uid types.UID)                { o.mutableMeta().SetUID(uid) }
func (o *Object) SetGeneration(generation int64)      { o.mutableMeta().SetGeneration(generation) }
func (o *Object) SetSelfLink(selfLink string)         { o.mutableMeta().SetSelfLink(selfLink) }
func (o *Object) SetLabels(labels map[string]string)  { o.mutableMeta().SetLabels(labels) }
func (o *Object) SetFinalizers(finalizers []string)   { o.mutableMeta().SetFinalizers(finalizers) }
func (o *Object) SetAnnotations(a map[string]string)  { o.mutableMeta().SetAnnotations(a) }
func (o *Object) SetCreationTimestamp(t metav1.Time)  { o.mutableMeta().SetCreationTimestamp(t) }
func (o *Object) SetDeletionTimestamp(t *metav1.Time) { o.mutableMeta().SetDeletionTimestamp(t) }
func (o *Object) SetDeletionGracePeriodSeconds(s *int64) {
	o.mutableMeta().SetDeletionGracePeriodSeconds(s)
}
func (o *Object) SetOwnerReferences(refs []metav1.OwnerReference) {
	o.mutableMeta().SetOwnerReferences(refs)
}
func (o *Object) SetManagedFields(mf []metav1.ManagedFieldsEntry) {
	o.mutableMeta().SetManagedFields(mf)
}

// Decoded returns obj itself, or its decoded form if it is serialized. Use it
// where the concrete API type is needed.
func Decoded(obj runtime.Object) (runtime.Object, error) {
	if s, ok := obj.(runtime.SerializedObject); ok {
		return s.DecodedObject()
	}
	return obj, nil
}

// ObjectMetaAttrs plucks the ObjectMeta part of Attrs. It is meant for
// AttrFuncs, which hand it the values their Plucker found at the paths
// NamePath, NamespacePath and LabelsPath.
type ObjectMetaAttrs struct {
	name, namespace []byte
	labels          labels.Set
}

var (
	// NamePath, NamespacePath and LabelsPath locate the corresponding
	// ObjectMeta fields in any Kubernetes API object.
	NamePath      = protopluck.Path{metadataField, 1}
	NamespacePath = protopluck.Path{metadataField, 3}
	LabelsPath    = protopluck.Path{metadataField, 11}
)

// SetName records a value plucked at NamePath.
func (m *ObjectMetaAttrs) SetName(v protopluck.Value) { m.name = v.Bytes }

// SetNamespace records a value plucked at NamespacePath.
func (m *ObjectMetaAttrs) SetNamespace(v protopluck.Value) { m.namespace = v.Bytes }

// AddLabel records a value plucked at LabelsPath, that is one label.
func (m *ObjectMetaAttrs) AddLabel(v protopluck.Value) error {
	key, value, err := v.MapEntry()
	if err != nil {
		return err
	}
	if m.labels == nil {
		m.labels = labels.Set{}
	}
	m.labels[string(key)] = string(value)
	return nil
}

// Attrs returns Attrs with everything but Fields filled in.
func (m *ObjectMetaAttrs) Attrs() Attrs {
	return Attrs{Name: string(m.name), Namespace: string(m.namespace), Labels: m.labels}
}
