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

package pod

import (
	"bytes"
	"io"
	"math/rand"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	apiv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/apitesting/fuzzer"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
	"k8s.io/apiserver/pkg/storage/rawobject"
	storagetesting "k8s.io/apiserver/pkg/storage/testing"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	apitesting "k8s.io/kubernetes/pkg/api/testing"
	api "k8s.io/kubernetes/pkg/apis/core"
	_ "k8s.io/kubernetes/pkg/apis/core/install"
)

// rawTestCodecs mirrors what a kube-apiserver uses for pods: protobuf in
// storage, and v1 protobuf or JSON on the wire.
type rawTestCodecs struct {
	storage      runtime.Codec
	protoEncoder runtime.Encoder
	jsonEncoder  runtime.Encoder
	factory      *rawobject.Factory
}

func newRawTestCodecs(t testing.TB) rawTestCodecs {
	proto := protobuf.NewSerializer(legacyscheme.Scheme, legacyscheme.Scheme)
	json, ok := runtime.SerializerInfoForMediaType(legacyscheme.Codecs.SupportedMediaTypes(), runtime.ContentTypeJSON)
	if !ok {
		t.Fatal("no JSON serializer")
	}
	c := rawTestCodecs{
		storage:      legacyscheme.Codecs.CodecForVersions(proto, legacyscheme.Codecs.UniversalDeserializer(), apiv1.SchemeGroupVersion, api.SchemeGroupVersion),
		protoEncoder: legacyscheme.Codecs.EncoderForVersion(proto, apiv1.SchemeGroupVersion),
		jsonEncoder:  legacyscheme.Codecs.EncoderForVersion(json.Serializer, apiv1.SchemeGroupVersion),
	}
	c.factory = rawobject.NewFactory(*RawWatchObjects(), func(value []byte, rev int64) (runtime.Object, error) {
		obj, err := runtime.Decode(c.storage, value)
		if err != nil {
			return nil, err
		}
		obj.(*api.Pod).ResourceVersion = "42"
		return obj, nil
	})
	return c
}

// store returns pod the way it ends up in etcd.
func (c rawTestCodecs) store(t testing.TB, pod *api.Pod) []byte {
	// The first trip through the codec applies the defaults a pod picks up on its way in.
	value, err := runtime.Encode(c.storage, pod)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := runtime.Decode(c.storage, value)
	if err != nil {
		t.Fatal(err)
	}
	obj.(*api.Pod).ResourceVersion = ""
	value, err = runtime.Encode(c.storage, obj)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// TestRawPodMatchesDecodedPod checks, on fuzzed pods, that not decoding a pod
// is unobservable: selectors see the same attributes, and watchers receive
// the same bytes.
func TestRawPodMatchesDecodedPod(t *testing.T) {
	c := newRawTestCodecs(t)
	seed := rand.Int63()
	t.Logf("seed: %d", seed)
	f := fuzzer.FuzzerFor(apitesting.FuzzerFuncs, rand.NewSource(seed), legacyscheme.Codecs)

	for i := 0; i < 500; i++ {
		pod := &api.Pod{}
		f.Fill(pod)
		value := c.store(t, pod)

		decoded, err := runtime.Decode(c.storage, value)
		if err != nil {
			t.Fatal(err)
		}
		decoded.(*api.Pod).ResourceVersion = "42"

		raw, ok := c.factory.New(value, 42)
		if !ok {
			t.Fatalf("pod was not kept serialized: %#v", pod)
		}

		wantLabels, wantFields, err := GetAttrs(decoded)
		if err != nil {
			t.Fatal(err)
		}
		gotLabels, gotFields, err := GetAttrs(raw)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(wantLabels, gotLabels, cmpopts.EquateEmpty()); diff != "" {
			t.Fatalf("labels differ (-decoded +raw):\n%s", diff)
		}
		if diff := cmp.Diff(wantFields, gotFields); diff != "" {
			t.Fatalf("fields differ (-decoded +raw):\n%s", diff)
		}
		if raw.GetName() != pod.Name || raw.GetNamespace() != pod.Namespace || raw.GetResourceVersion() != "42" {
			t.Fatalf("unexpected identity %s/%s@%s", raw.GetNamespace(), raw.GetName(), raw.GetResourceVersion())
		}
		if want, got := NodeNameTriggerFunc(decoded), NodeNameTriggerFunc(raw); want != got {
			t.Fatalf("trigger value: decoded %q, raw %q", want, got)
		}

		for name, encoder := range map[string]runtime.Encoder{"protobuf": c.protoEncoder, "json": c.jsonEncoder} {
			want, err := runtime.Encode(encoder, decoded)
			if err != nil {
				t.Fatal(err)
			}
			got, err := runtime.Encode(encoder, raw)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(want, got) {
				t.Fatalf("%s encoding differs for pod %#v\ndecoded: %x\nraw:     %x", name, pod, want, got)
			}
		}

		// A delete event reports the pod at the revision of the delete.
		deleted := raw.DeepCopyObject().(*rawobject.Object)
		deleted.SetResourceVersion("43")
		decoded.(*api.Pod).ResourceVersion = "43"
		want, err := runtime.Encode(c.protoEncoder, decoded)
		if err != nil {
			t.Fatal(err)
		}
		got, err := runtime.Encode(c.protoEncoder, deleted)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("encoding of deleted pod differs")
		}
		if raw.GetResourceVersion() != "42" {
			t.Fatalf("setting the resourceVersion of a copy changed the original")
		}
	}
}

// TestRawPodIsNotDecoded pins down the point of the exercise.
func TestRawPodIsNotDecoded(t *testing.T) {
	c := newRawTestCodecs(t)
	decodes := 0
	factory := rawobject.NewFactory(*RawWatchObjects(), func(value []byte, rev int64) (runtime.Object, error) {
		decodes++
		return runtime.Decode(c.storage, value)
	})
	pod := &api.Pod{}
	pod.Name, pod.Namespace, pod.Labels = "a", "ns", map[string]string{"k": "v"}
	pod.Spec.NodeName = "node"
	raw, ok := factory.New(c.store(t, pod), 7)
	if !ok {
		t.Fatal("pod was not kept serialized")
	}
	if _, _, err := GetAttrs(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Encode(c.protoEncoder, raw); err != nil {
		t.Fatal(err)
	}
	if decodes != 0 {
		t.Fatalf("pod was decoded %d times on the protobuf path", decodes)
	}
	if _, err := runtime.Encode(c.jsonEncoder, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Encode(c.jsonEncoder, raw); err != nil {
		t.Fatal(err)
	}
	if decodes != 1 {
		t.Fatalf("pod was decoded %d times for two JSON encodings, expected 1", decodes)
	}
}

// BenchmarkWatchEvent measures what one pod event costs the apiserver between
// reading it from etcd and having it ready to send to protobuf watchers:
// producing an object, computing what selectors need, and encoding it.
// Sending is per watcher and the same either way, so it is left out.
func BenchmarkWatchEvent(b *testing.B) {
	c := newRawTestCodecs(b)
	data := storagetesting.PrepareBenchmarkData(1, 100, 30)
	values := make([][]byte, len(data.Pods))
	size := 0
	for i, v1Pod := range data.Pods {
		pod := &api.Pod{}
		if err := legacyscheme.Scheme.Convert(v1Pod, pod, nil); err != nil {
			b.Fatal(err)
		}
		values[i] = c.store(b, pod)
		size += len(values[i])
	}
	b.Logf("average stored pod: %d bytes", size/len(values))

	b.Run("decoded", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			obj, err := runtime.Decode(c.storage, values[i%len(values)])
			if err != nil {
				b.Fatal(err)
			}
			pod := obj.(*api.Pod)
			pod.ResourceVersion = "12345678"
			if _, _, err := GetAttrs(pod); err != nil {
				b.Fatal(err)
			}
			// The watch cache keeps the object, and hands a copy to the encoder.
			if err := c.protoEncoder.Encode(pod.DeepCopyObject(), io.Discard); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("raw", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			raw, ok := c.factory.New(values[i%len(values)], 12345678)
			if !ok {
				b.Fatal("pod was not kept serialized")
			}
			if _, _, err := GetAttrs(raw); err != nil {
				b.Fatal(err)
			}
			if err := c.protoEncoder.Encode(raw.DeepCopyObject(), io.Discard); err != nil {
				b.Fatal(err)
			}
		}
	})
}
