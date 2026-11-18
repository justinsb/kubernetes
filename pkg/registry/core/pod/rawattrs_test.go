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
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	apiv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/apitesting/fuzzer"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apiserver/pkg/storage/rawobject"
	storagetesting "k8s.io/apiserver/pkg/storage/testing"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/component-base/featuregate"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	apitesting "k8s.io/kubernetes/pkg/api/testing"
	api "k8s.io/kubernetes/pkg/apis/core"
	_ "k8s.io/kubernetes/pkg/apis/core/install"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/utils/ptr"
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

// checkRawMatchesDecoded reports whether the stored pod is kept serialized.
// If it is, it checks that this is unobservable: selectors see the attributes
// of the decoded pod, and watchers receive the bytes they would have.
func checkRawMatchesDecoded(t *testing.T, c rawTestCodecs, value []byte) bool {
	t.Helper()
	raw, ok := c.factory.New(value, 42)
	if !ok {
		return false
	}
	decoded, err := runtime.Decode(c.storage, value)
	if err != nil {
		t.Fatal(err)
	}
	pod := decoded.(*api.Pod)
	pod.ResourceVersion = "42"

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
			t.Fatalf("%s encoding differs, the pod should not have been kept serialized:\n%s", name, cmp.Diff(c.unmarshal(t, got), c.unmarshal(t, want)))
		}
	}

	// A delete event reports the pod at the revision of the delete.
	deleted := raw.DeepCopyObject().(*rawobject.Object)
	deleted.SetResourceVersion("43")
	pod.ResourceVersion = "43"
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
	return true
}

// unmarshal returns the v1 pod in a protobuf encoded value as it is, without
// the defaulting that decoding with a codec comes with.
func (c rawTestCodecs) unmarshal(t testing.TB, value []byte) *apiv1.Pod {
	t.Helper()
	unk := &runtime.Unknown{}
	if err := unk.Unmarshal(value[4:]); err != nil {
		t.Fatal(err)
	}
	pod := &apiv1.Pod{}
	if err := pod.Unmarshal(unk.Raw); err != nil {
		t.Fatal(err)
	}
	return pod
}

// marshal is the reverse of unmarshal: it encodes the pod as it is.
func (c rawTestCodecs) marshal(t testing.TB, pod *apiv1.Pod) []byte {
	t.Helper()
	raw, err := pod.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	unk := &runtime.Unknown{TypeMeta: runtime.TypeMeta{APIVersion: "v1", Kind: "Pod"}, Raw: raw}
	data, err := unk.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte("k8s\x00"), data...)
}

// richPod uses every part of a pod that defaulting touches and that pods are
// kept serialized with.
func richPod() *api.Pod {
	probe := func(handler api.ProbeHandler) *api.Probe {
		return &api.Probe{ProbeHandler: handler, InitialDelaySeconds: 5}
	}
	httpGet := &api.HTTPGetAction{Port: intstr.FromInt32(8080)}
	container := func(name string) api.Container {
		return api.Container{
			Name:  name,
			Image: "registry.example.com/" + name,
			Ports: []api.ContainerPort{{Name: "http", ContainerPort: 8080}, {ContainerPort: 9090, HostPort: 9091, Protocol: api.ProtocolUDP}},
			Env: []api.EnvVar{
				{Name: "PLAIN", Value: "value"},
				{Name: "NODE", ValueFrom: &api.EnvVarSource{FieldRef: &api.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
				{Name: "SECRET", ValueFrom: &api.EnvVarSource{SecretKeyRef: &api.SecretKeySelector{Key: "key"}}},
				{Name: "FILE", ValueFrom: &api.EnvVarSource{FileKeyRef: &api.FileKeySelector{VolumeName: "scratch", Path: "env", Key: "key"}}},
			},
			Resources: api.ResourceRequirements{
				Limits:   api.ResourceList{api.ResourceCPU: resource.MustParse("500m"), api.ResourceMemory: resource.MustParse("64Mi")},
				Requests: api.ResourceList{api.ResourceCPU: resource.MustParse("250m")},
			},
			LivenessProbe:  probe(api.ProbeHandler{HTTPGet: httpGet.DeepCopy()}),
			ReadinessProbe: probe(api.ProbeHandler{GRPC: &api.GRPCAction{Port: 9090}}),
			StartupProbe:   probe(api.ProbeHandler{TCPSocket: &api.TCPSocketAction{Port: intstr.FromInt32(8080)}}),
			Lifecycle: &api.Lifecycle{
				PostStart: &api.LifecycleHandler{HTTPGet: httpGet.DeepCopy()},
				PreStop:   &api.LifecycleHandler{Exec: &api.ExecAction{Command: []string{"stop"}}},
			},
		}
	}
	downwardAPIItems := []api.DownwardAPIVolumeFile{
		{Path: "name", FieldRef: &api.ObjectFieldSelector{FieldPath: "metadata.name"}},
		{Path: "cpu", ResourceFieldRef: &api.ResourceFieldSelector{ContainerName: "main", Resource: "limits.cpu"}},
	}
	statuses := []api.ContainerStatus{{
		Name:               "main",
		AllocatedResources: api.ResourceList{api.ResourceCPU: resource.MustParse("250m")},
		Resources:          &api.ResourceRequirements{Limits: api.ResourceList{api.ResourceCPU: resource.MustParse("500m")}},
	}}
	return &api.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rich", Labels: map[string]string{"app": "rich"}, Annotations: map[string]string{"a": "b"}},
		Spec: api.PodSpec{
			NodeName:            "node",
			ServiceAccountName:  "account",
			InitContainers:      []api.Container{container("init")},
			Containers:          []api.Container{container("main"), container("sidecar")},
			EphemeralContainers: []api.EphemeralContainer{{EphemeralContainerCommon: api.EphemeralContainerCommon(container("debug"))}},
			Overhead:            api.ResourceList{api.ResourceMemory: resource.MustParse("16Mi")},
			Resources:           &api.ResourceRequirements{Limits: api.ResourceList{api.ResourceCPU: resource.MustParse("2")}, Requests: api.ResourceList{api.ResourceCPU: resource.MustParse("1")}},
			Volumes: []api.Volume{
				{Name: "scratch", VolumeSource: api.VolumeSource{EmptyDir: &api.EmptyDirVolumeSource{}}},
				{Name: "host", VolumeSource: api.VolumeSource{HostPath: &api.HostPathVolumeSource{Path: "/var/log"}}},
				{Name: "secret", VolumeSource: api.VolumeSource{Secret: &api.SecretVolumeSource{SecretName: "s"}}},
				{Name: "config", VolumeSource: api.VolumeSource{ConfigMap: &api.ConfigMapVolumeSource{LocalObjectReference: api.LocalObjectReference{Name: "c"}}}},
				{Name: "claim", VolumeSource: api.VolumeSource{PersistentVolumeClaim: &api.PersistentVolumeClaimVolumeSource{ClaimName: "pvc"}}},
				{Name: "info", VolumeSource: api.VolumeSource{DownwardAPI: &api.DownwardAPIVolumeSource{Items: downwardAPIItems}}},
				{Name: "token", VolumeSource: api.VolumeSource{Projected: &api.ProjectedVolumeSource{Sources: []api.VolumeProjection{
					{ServiceAccountToken: &api.ServiceAccountTokenProjection{Path: "token"}},
					{ConfigMap: &api.ConfigMapProjection{LocalObjectReference: api.LocalObjectReference{Name: "kube-root-ca.crt"}}},
					{DownwardAPI: &api.DownwardAPIProjection{Items: downwardAPIItems}},
				}}}},
			},
		},
		Status: api.PodStatus{
			Phase:                      api.PodRunning,
			PodIP:                      "10.0.0.1",
			PodIPs:                     []api.PodIP{{IP: "10.0.0.1"}, {IP: "fd00::1"}},
			InitContainerStatuses:      statuses,
			ContainerStatuses:          statuses,
			EphemeralContainerStatuses: statuses,
			AllocatedResources:         api.ResourceList{api.ResourceCPU: resource.MustParse("1")},
			Resources:                  &api.ResourceRequirements{Limits: api.ResourceList{api.ResourceCPU: resource.MustParse("2")}},
		},
	}
}

// rawTestPods returns stored pods of three kinds: realistic ones, one that
// exercises every check, and fuzzed ones. Only the first two kinds are
// expected to be kept serialized.
func rawTestPods(t *testing.T, c rawTestCodecs, seed int64) (realistic, fuzzed [][]byte) {
	for _, v1Pod := range storagetesting.PrepareBenchmarkData(1, 5, 5).Pods {
		pod := &api.Pod{}
		if err := legacyscheme.Scheme.Convert(v1Pod, pod, nil); err != nil {
			t.Fatal(err)
		}
		realistic = append(realistic, c.store(t, pod))
	}
	realistic = append(realistic, c.store(t, richPod()))
	hostNetwork := richPod()
	hostNetwork.Spec.HostNetwork = true
	realistic = append(realistic, c.store(t, hostNetwork))

	f := fuzzer.FuzzerFor(apitesting.FuzzerFuncs, rand.NewSource(seed), legacyscheme.Codecs)
	for i := 0; i < 300; i++ {
		pod := &api.Pod{}
		f.Fill(pod)
		fuzzed = append(fuzzed, c.store(t, pod))
	}
	return realistic, fuzzed
}

// TestRawPodMatchesDecodedPod checks that pods in their defaulted state, which
// is how an apiserver stores them, are kept serialized, and that it does not
// show.
func TestRawPodMatchesDecodedPod(t *testing.T) {
	c := newRawTestCodecs(t)
	seed := rand.Int63()
	t.Logf("seed: %d", seed)
	realistic, fuzzed := rawTestPods(t, c, seed)
	for i, value := range realistic {
		if !checkRawMatchesDecoded(t, c, value) {
			t.Errorf("realistic pod %d was not kept serialized: %#v", i, c.unmarshal(t, value))
		}
	}
	kept := 0
	for _, value := range fuzzed {
		if checkRawMatchesDecoded(t, c, value) {
			kept++
		}
	}
	// Fuzzed pods are full of what the detection does not bother with.
	t.Logf("%d of %d fuzzed pods were kept serialized", kept, len(fuzzed))
}

// TestRawPodDefaultingDetection checks that a pod is only kept serialized if
// defaulting would not change it. It takes defaulted pods, damages them the
// way an older or differently configured writer could have left them, and
// requires those still kept serialized to encode exactly like the decoded,
// defaulted pod.
//
// This is what fails when pkg/apis/core/v1 gains a default: add the matching
// check to rawdefaults.go.
func TestRawPodDefaultingDetection(t *testing.T) {
	for name, gates := range map[string]map[featuregate.Feature]bool{
		"default gates":             {},
		"no http probe protocol":    {features.H2CContainerProbe: false},
		"pod resources set on read": {features.PodLevelResources: true, features.PodLevelResourcesFixDefaulting: false},
	} {
		t.Run(name, func(t *testing.T) {
			for gate, enabled := range gates {
				featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, gate, enabled)
			}
			c := newRawTestCodecs(t)
			seed := rand.Int63()
			t.Logf("seed: %d", seed)
			rng := rand.New(rand.NewSource(seed))
			realistic, fuzzed := rawTestPods(t, c, seed)

			// Realistic pods are where a missing check would hurt, and with
			// one to three fields reset per attempt, covering all of theirs
			// takes a good many attempts.
			kept, total := 0, 0
			for i, value := range append(realistic, fuzzed...) {
				attempts := 3000
				if i >= len(realistic) {
					attempts = 30
				}
				for ; attempts > 0; attempts-- {
					pod := c.unmarshal(t, value)
					damage(rng, pod)
					total++
					if checkRawMatchesDecoded(t, c, c.marshal(t, pod)) {
						kept++
					}
				}
			}
			t.Logf("%d of %d damaged pods were still kept serialized", kept, total)
		})
	}
}

// damage undoes some of what defaulting does to a pod: it resets a few fields
// picked at random anywhere in the pod, and now and then breaks one of the
// invariants defaulting maintains between fields.
func damage(rng *rand.Rand, pod *apiv1.Pod) {
	var resets []func()
	collectResets(reflect.ValueOf(pod).Elem(), rng, &resets)
	for n := 1 + rng.Intn(3); n > 0 && len(resets) > 0; n-- {
		resets[rng.Intn(len(resets))]()
	}

	containers := append(append([]apiv1.Container{}, pod.Spec.Containers...), pod.Spec.InitContainers...)
	switch rng.Intn(12) {
	case 0:
		pod.Status.PodIP = "192.0.2.1"
	case 1:
		pod.Status.PodIPs = append([]apiv1.PodIP{{IP: "192.0.2.2"}}, pod.Status.PodIPs...)
	case 2:
		pod.Spec.TerminationGracePeriodSeconds = ptr.To[int64](-1)
	case 3:
		pod.Spec.ServiceAccountName = "another"
	case 4:
		pod.Spec.DeprecatedServiceAccount = "another"
	case 5:
		pod.Spec.HostNetwork = true
	case 6:
		if len(containers) > 0 {
			c := containers[rng.Intn(len(containers))]
			if c.Resources.Limits == nil {
				c.Resources.Limits = apiv1.ResourceList{}
			}
			c.Resources.Limits["example.com/limited"] = resource.MustParse("1")
		}
	case 7:
		// A quantity, anywhere, finer than what defaulting rounds to.
		var lists []apiv1.ResourceList
		collectResourceLists(reflect.ValueOf(pod).Elem(), &lists)
		if len(lists) > 0 {
			list := lists[rng.Intn(len(lists))]
			for name := range list {
				list[name] = resource.MustParse("1500u")
				break
			}
		}
	}
}

// collectResourceLists appends every non-empty ResourceList found in v.
func collectResourceLists(v reflect.Value, lists *[]apiv1.ResourceList) {
	if list, ok := v.Interface().(apiv1.ResourceList); ok {
		if len(list) > 0 {
			*lists = append(*lists, list)
		}
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			collectResourceLists(v.Elem(), lists)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				collectResourceLists(v.Field(i), lists)
			}
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			collectResourceLists(v.Index(i), lists)
		}
	}
}

// collectResets walks v and appends, for everything that is set in it, a
// function that unsets it.
func collectResets(v reflect.Value, rng *rand.Rand, resets *[]func()) {
	switch v.Type() {
	case reflect.TypeFor[resource.Quantity](), reflect.TypeFor[metav1.Time](), reflect.TypeFor[metav1.ObjectMeta]():
		// Opaque values, and metadata, which has no defaults and has to keep the pod identifiable.
		return
	}
	reset := func() { v.SetZero() }
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			*resets = append(*resets, reset)
			collectResets(v.Elem(), rng, resets)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				collectResets(v.Field(i), rng, resets)
			}
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			collectResets(v.Index(i), rng, resets)
		}
	case reflect.Map:
		if keys := v.MapKeys(); len(keys) > 0 {
			key := keys[rng.Intn(len(keys))]
			*resets = append(*resets, func() { v.SetMapIndex(key, reflect.Value{}) })
		}
	default:
		if !v.IsZero() {
			*resets = append(*resets, reset)
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
