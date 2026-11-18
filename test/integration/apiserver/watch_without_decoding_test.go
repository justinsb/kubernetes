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

package apiserver

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/storage/rawobject"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	kubeapiservertesting "k8s.io/kubernetes/cmd/kube-apiserver/app/testing"
	"k8s.io/kubernetes/test/integration/framework"
)

// podEvent is what a watcher is expected to observe, or did observe.
type podEvent struct {
	Type watch.EventType
	Pod  *v1.Pod
}

// TestWatchWithoutDecoding runs pods through their lifecycle while watching
// them over protobuf, which is served from stored bytes, and over JSON, which
// has to decode them. The two have to tell the same story, whatever the
// selector. It also checks that the protobuf watches really were served
// without decoding, as the story alone cannot tell.
func TestWatchWithoutDecoding(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.WatchWithoutDecoding, true)

	server := kubeapiservertesting.StartTestServerOrDie(t, nil, framework.DefaultTestServerFlags(), framework.SharedEtcd())
	defer server.TearDownFn()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	jsonClient := clientset.NewForConfigOrDie(server.ClientConfig)
	protoConfig := rest.CopyConfig(server.ClientConfig)
	protoConfig.ContentType = runtime.ContentTypeProtobuf
	protoConfig.AcceptContentTypes = runtime.ContentTypeProtobuf
	protoClient := clientset.NewForConfigOrDie(protoConfig)

	ns := "watch-without-decoding"
	if _, err := jsonClient.CoreV1().Namespaces().Create(ctx, &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := jsonClient.CoreV1().ServiceAccounts(ns).Create(ctx, &v1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "default"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// A pod that exists before any watch starts, whose later events depend
	// on what the watch cache held for it from the start.
	if _, err := jsonClient.CoreV1().Pods(ns).Create(ctx, testPod("existing", map[string]string{"app": "a"}, ""), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	list, err := jsonClient.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}

	selectors := map[string]metav1.ListOptions{
		"everything":     {},
		"label":          {LabelSelector: "app=a"},
		"label set":      {LabelSelector: "app in (a,c),tier"},
		"node":           {FieldSelector: "spec.nodeName=node-1"},
		"name":           {FieldSelector: "metadata.name!=stays"},
		"phase":          {FieldSelector: "status.phase!=Running"},
		"label and node": {LabelSelector: "app=a", FieldSelector: "spec.nodeName=node-1"},
	}
	type watchers struct{ proto, json watch.Interface }
	started := map[string]watchers{}
	for name, opts := range selectors {
		opts.ResourceVersion = list.ResourceVersion
		pw, err := protoClient.CoreV1().Pods(ns).Watch(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		defer pw.Stop()
		jw, err := jsonClient.CoreV1().Pods(ns).Watch(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		defer jw.Stop()
		started[name] = watchers{proto: pw, json: jw}
	}

	before := rawobject.ReadStats()

	// Each step changes what some selector matches.
	pods := protoClient.CoreV1().Pods(ns)
	mustDo := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	_, err = pods.Create(ctx, testPod("stays", map[string]string{"app": "a", "tier": "web"}, "node-1"), metav1.CreateOptions{})
	mustDo("create stays", err)
	_, err = pods.Create(ctx, testPod("moves", map[string]string{"app": "b"}, ""), metav1.CreateOptions{})
	mustDo("create moves", err)
	mustDo("bind moves", pods.Bind(ctx, &v1.Binding{ObjectMeta: metav1.ObjectMeta{Name: "moves"}, Target: v1.ObjectReference{Kind: "Node", Name: "node-1"}}, metav1.CreateOptions{}))
	moves, err := pods.Get(ctx, "moves", metav1.GetOptions{})
	mustDo("get moves", err)
	moves.Labels = map[string]string{"app": "a"}
	moves, err = pods.Update(ctx, moves, metav1.UpdateOptions{})
	mustDo("relabel moves", err)
	moves.Status.Phase = v1.PodRunning
	moves, err = pods.UpdateStatus(ctx, moves, metav1.UpdateOptions{})
	mustDo("run moves", err)
	moves.Labels = map[string]string{"app": "c", "tier": "db"}
	_, err = pods.Update(ctx, moves, metav1.UpdateOptions{})
	mustDo("relabel moves again", err)
	zero := int64(0)
	mustDo("delete stays", pods.Delete(ctx, "stays", metav1.DeleteOptions{GracePeriodSeconds: &zero}))
	mustDo("delete moves", pods.Delete(ctx, "moves", metav1.DeleteOptions{GracePeriodSeconds: &zero}))
	mustDo("delete existing", pods.Delete(ctx, "existing", metav1.DeleteOptions{GracePeriodSeconds: &zero}))
	// The end of the story, visible to every selector that saw any of it.
	final, err := pods.Create(ctx, testPod("end", map[string]string{"app": "a", "tier": "end"}, "node-1"), metav1.CreateOptions{})
	mustDo("create end", err)

	total := 0
	for name, w := range started {
		t.Logf("collecting events for selector %q", name)
		fromJSON := collectPodEvents(t, ctx, w.json, final.ResourceVersion)
		fromProto := collectPodEvents(t, ctx, w.proto, final.ResourceVersion)
		if diff := cmp.Diff(fromJSON, fromProto); diff != "" {
			t.Errorf("selector %q: watches disagree (-json +protobuf):\n%s", name, diff)
		}
		if len(fromProto) < 2 {
			t.Errorf("selector %q: only saw %d events, the test is not testing much", name, len(fromProto))
		}
		total += len(fromProto)
	}

	// With JSON watchers around, every pod gets decoded for them. Once they
	// are gone, nothing should decode a pod that is merely watched. The
	// server notices their departure asynchronously, hence the retries.
	for _, w := range started {
		w.json.Stop()
	}
	everything := started["everything"].proto
	undecoded := false
	for i := 0; i < 20 && !undecoded; i++ {
		stats := rawobject.ReadStats()
		pod, err := pods.Create(ctx, testPod(fmt.Sprintf("undecoded-%d", i), map[string]string{"app": "a"}, "node-1"), metav1.CreateOptions{})
		mustDo("create pod", err)
		collectPodEvents(t, ctx, everything, pod.ResourceVersion)
		now := rawobject.ReadStats()
		undecoded = now.Created > stats.Created && now.PassedThrough > stats.PassedThrough && now.Decoded == stats.Decoded
		time.Sleep(50 * time.Millisecond)
	}
	if !undecoded {
		t.Errorf("pods watched over protobuf only were still decoded")
	}

	after := rawobject.ReadStats()
	t.Logf("%d protobuf events delivered; objects kept serialized: %d, written from stored bytes: %d, decoded after all: %d",
		total, after.Created-before.Created, after.PassedThrough-before.PassedThrough, after.Decoded-before.Decoded)
	if after.Created == before.Created {
		t.Errorf("no pod was kept serialized")
	}
	if after.PassedThrough == before.PassedThrough {
		t.Errorf("no pod was written from its stored bytes")
	}
}

func testPod(name string, labels map[string]string, nodeName string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels, Annotations: map[string]string{"note": fmt.Sprintf("pod %s", name)}},
		Spec: v1.PodSpec{
			NodeName:   nodeName,
			Containers: []v1.Container{{Name: "c", Image: "registry.k8s.io/pause:3.10"}},
		},
	}
}

// collectPodEvents reads events until the one at lastResourceVersion.
func collectPodEvents(t *testing.T, ctx context.Context, w watch.Interface, lastResourceVersion string) []podEvent {
	t.Helper()
	var events []podEvent
	for {
		select {
		case event, ok := <-w.ResultChan():
			if !ok {
				t.Fatalf("watch closed after %d events", len(events))
			}
			if event.Type == watch.Bookmark {
				continue
			}
			pod, ok := event.Object.(*v1.Pod)
			if !ok {
				t.Fatalf("unexpected %s event with %T: %v", event.Type, event.Object, event.Object)
			}
			events = append(events, podEvent{Type: event.Type, Pod: pod})
			if pod.ResourceVersion == lastResourceVersion {
				return events
			}
		case <-ctx.Done():
			t.Fatalf("timed out after %d events", len(events))
		}
	}
}

// TestWatchWithoutDecodingAppliesDefaults plants a pod in etcd the way an
// apiserver that knew fewer defaults would have written it. Such a pod has to
// be decoded, so that protobuf watchers get those defaults like anyone else.
// Once the pod is written again, by this apiserver, it no longer needs to be.
func TestWatchWithoutDecodingAppliesDefaults(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.WatchWithoutDecoding, true)

	server := kubeapiservertesting.StartTestServerOrDie(t, nil, framework.DefaultTestServerFlags(), framework.SharedEtcd())
	defer server.TearDownFn()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	config := rest.CopyConfig(server.ClientConfig)
	config.ContentType = runtime.ContentTypeProtobuf
	config.AcceptContentTypes = runtime.ContentTypeProtobuf
	client := clientset.NewForConfigOrDie(config)

	ns := "watch-without-decoding-defaults"
	if _, err := client.CoreV1().Namespaces().Create(ctx, &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CoreV1().ServiceAccounts(ns).Create(ctx, &v1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "default"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	pods := client.CoreV1().Pods(ns)
	pod := testPod("old", map[string]string{"app": "a"}, "node-1")
	pod.Spec.Containers[0].LivenessProbe = &v1.Probe{ProbeHandler: v1.ProbeHandler{HTTPGet: &v1.HTTPGetAction{Port: intstr.FromInt32(8080)}}}
	created, err := pods.Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	w, err := pods.Watch(ctx, metav1.ListOptions{ResourceVersion: created.ResourceVersion})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	// Rewrite the pod behind the apiserver's back, without some defaults: an
	// old one, and the most recent one.
	key := "/" + server.EtcdStoragePrefix + "/pods/" + ns + "/old"
	stored, err := server.EtcdClient.Get(ctx, key)
	if err != nil || len(stored.Kvs) != 1 {
		t.Fatalf("reading %s from etcd: %v, %d values", key, err, len(stored.Kvs))
	}
	magic := []byte("k8s\x00")
	envelope := &runtime.Unknown{}
	if err := envelope.Unmarshal(bytes.TrimPrefix(stored.Kvs[0].Value, magic)); err != nil {
		t.Fatal(err)
	}
	old := &v1.Pod{}
	if err := old.Unmarshal(envelope.Raw); err != nil {
		t.Fatal(err)
	}
	if old.Spec.DNSPolicy == "" || old.Spec.Containers[0].LivenessProbe.TimeoutSeconds == 0 {
		t.Fatalf("the pod is not stored defaulted, which this test builds on: %v", old)
	}
	old.Spec.DNSPolicy = ""
	old.Spec.Containers[0].LivenessProbe.TimeoutSeconds = 0
	old.Spec.Containers[0].LivenessProbe.HTTPGet.Protocol = nil
	if envelope.Raw, err = old.Marshal(); err != nil {
		t.Fatal(err)
	}
	value, err := envelope.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	before := rawobject.ReadStats()
	put, err := server.EtcdClient.Put(ctx, key, string(append(magic, value...)))
	if err != nil {
		t.Fatal(err)
	}

	planted := collectPodEvents(t, ctx, w, fmt.Sprint(put.Header.Revision))
	watched := planted[len(planted)-1].Pod
	// Reading the pod decodes it, which is the reference for what clients should see.
	read, err := pods.Get(ctx, "old", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(read, watched); diff != "" {
		t.Errorf("the pod as watched differs from the pod as read (-read +watched):\n%s", diff)
	}
	if watched.Spec.DNSPolicy == "" || watched.Spec.Containers[0].LivenessProbe.TimeoutSeconds == 0 {
		t.Errorf("the watched pod lacks the defaults that were removed from storage: %v", watched)
	}
	if after := rawobject.ReadStats(); after.Created != before.Created {
		t.Errorf("a pod that needs defaulting was kept serialized")
	}

	// Any write through the apiserver stores the pod defaulted again.
	before = rawobject.ReadStats()
	read.Labels["app"] = "b"
	updated, err := pods.Update(ctx, read, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rewritten := collectPodEvents(t, ctx, w, updated.ResourceVersion)
	if diff := cmp.Diff(updated, rewritten[len(rewritten)-1].Pod); diff != "" {
		t.Errorf("the pod as watched differs from the pod as updated (-updated +watched):\n%s", diff)
	}
	if after := rawobject.ReadStats(); after.Created == before.Created {
		t.Errorf("the pod was not kept serialized after being written with its defaults")
	}
}
