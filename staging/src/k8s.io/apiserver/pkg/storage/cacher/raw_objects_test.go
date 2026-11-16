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

package cacher

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/etcd3"
	etcd3testing "k8s.io/apiserver/pkg/storage/etcd3/testing"
	"k8s.io/apiserver/pkg/storage/etcd3/testserver"
	"k8s.io/apiserver/pkg/storage/rawobject"
	storagetesting "k8s.io/apiserver/pkg/storage/testing"
	"k8s.io/apiserver/pkg/storage/value/encrypt/identity"
	"k8s.io/utils/clock"
)

// newRawObjectsTestCacher returns a cacher on top of an etcd store that keeps
// watched pods serialized, along with that store.
func newRawObjectsTestCacher(t testing.TB) (*Cacher, storage.Interface) {
	config := storagetesting.StoreConfigForBenchmarks()
	client := testserver.RunEtcd(t)
	compactor := etcd3.NewCompactor(client.Client, 0, clock.RealClock{}, nil)
	t.Cleanup(compactor.Stop)
	store, err := etcd3.New(
		client,
		compactor,
		config.Codec,
		config.NewFunc,
		config.NewListFunc,
		storagetesting.PodReverseKeyFunc(config.ResourcePrefix, true),
		etcd3testing.PathPrefix(),
		config.ResourcePrefix,
		config.GroupResource,
		identity.NewEncryptCheckTransformer(),
		etcd3.NewDefaultLeaseManagerConfig(),
		etcd3.NewDefaultDecoder(config.Codec, config.Versioner),
		config.Versioner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	store.SetRawWatchObjects(storagetesting.RawWatchObjectsForBenchmarks())

	nodeName := func(obj runtime.Object) string {
		if raw, ok := obj.(*rawobject.Object); ok {
			return raw.Attrs().Fields["spec.nodeName"]
		}
		return obj.(*corev1.Pod).Spec.NodeName
	}
	cacher, err := NewCacherFromConfig(Config{
		Storage:             store,
		Versioner:           config.Versioner,
		GroupResource:       config.GroupResource,
		EventsHistoryWindow: DefaultEventFreshDuration,
		ResourcePrefix:      config.ResourcePrefix,
		KeyFunc:             config.KeyFunc,
		GetAttrsFunc:        config.GetAttrsFunc,
		IndexerFuncs:        storage.IndexerFuncs{"spec.nodeName": nodeName},
		NewFunc:             config.NewFunc,
		NewListFunc:         config.NewListFunc,
		Codec:               config.Codec,
		Clock:               clock.RealClock{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cacher.Stop)
	if err := cacher.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	return cacher, store
}

func rawTestPod(name string, podLabels map[string]string, nodeName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name, Labels: podLabels, Annotations: map[string]string{"pod": name}},
		Spec:       corev1.PodSpec{NodeName: nodeName, Containers: []corev1.Container{{Name: "c", Image: "image"}}},
	}
}

// TestCacherWithRawObjects drives pods through a cacher fed with serialized
// objects, and checks that watchers get them without them being decoded, that
// what they get encodes to what the decoded pods would have, and that readers
// who need actual pods still get those.
func TestCacherWithRawObjects(t *testing.T) {
	cacher, store := newRawObjectsTestCacher(t)
	ctx, cancel := context.WithTimeout(context.Background(), wait.ForeverTestTimeout)
	defer cancel()
	codec := storagetesting.StoreConfigForBenchmarks().Codec

	// A pod that predates the watchers, to be read back through the cache later.
	listed := &corev1.Pod{}
	if err := store.Create(ctx, "/pods/ns/listed", rawTestPod("listed", map[string]string{"app": "a"}, "node-1"), listed, 0); err != nil {
		t.Fatal(err)
	}

	// One watcher per dispatch path: selected by labels, and selected through the trigger index.
	predicate := func(label, field string) storage.SelectionPredicate {
		p := storage.SelectionPredicate{Label: labels.Everything(), Field: fields.Everything(), GetAttrs: cacher.watchCache.config.getAttrsFunc}
		if label != "" {
			p.Label = labels.SelectorFromSet(labels.Set{"app": label})
		}
		if field != "" {
			p.Field = fields.OneTermEqualSelector("spec.nodeName", field)
		}
		return p
	}
	startWatch := func(label, field, rv string) watch.Interface {
		w, err := cacher.Watch(ctx, "/pods/ns/", storage.ListOptions{ResourceVersion: rv, Recursive: true, Predicate: predicate(label, field)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(w.Stop)
		return w
	}
	byLabel := startWatch("a", "", listed.ResourceVersion)
	byNode := startWatch("", "node-1", listed.ResourceVersion)

	before := rawobject.ReadStats()

	created := &corev1.Pod{}
	if err := store.Create(ctx, "/pods/ns/pod", rawTestPod("pod", map[string]string{"app": "b"}, "node-1"), created, 0); err != nil {
		t.Fatal(err)
	}
	relabeled := &corev1.Pod{}
	if err := store.GuaranteedUpdate(ctx, "/pods/ns/pod", relabeled, false, nil, storage.SimpleUpdate(func(obj runtime.Object) (runtime.Object, error) {
		pod := obj.(*corev1.Pod).DeepCopy()
		pod.Labels = map[string]string{"app": "a"}
		return pod, nil
	}), nil); err != nil {
		t.Fatal(err)
	}
	moved := &corev1.Pod{}
	if err := store.GuaranteedUpdate(ctx, "/pods/ns/pod", moved, false, nil, storage.SimpleUpdate(func(obj runtime.Object) (runtime.Object, error) {
		pod := obj.(*corev1.Pod).DeepCopy()
		pod.Spec.NodeName = "node-2"
		return pod, nil
	}), nil); err != nil {
		t.Fatal(err)
	}
	deleted := &corev1.Pod{}
	if err := store.Delete(ctx, "/pods/ns/pod", deleted, nil, storage.ValidateAllObjectFunc, nil, storage.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	// Deletion reports the last state of the pod at the revision it went away.
	gone := moved.DeepCopy()
	gone.ResourceVersion = deleted.ResourceVersion
	// To the node-1 watcher, the pod is gone as soon as it moves.
	movedAway := relabeled.DeepCopy()
	movedAway.ResourceVersion = moved.ResourceVersion

	type event struct {
		Type watch.EventType
		Pod  *corev1.Pod
	}
	expect := func(name string, w watch.Interface, want []event) {
		t.Helper()
		for i, e := range want {
			var got watch.Event
			select {
			case got = <-w.ResultChan():
			case <-ctx.Done():
				t.Fatalf("%s: timed out waiting for event %d", name, i)
			}
			if got.Type != e.Type {
				t.Fatalf("%s: event %d is %s, expected %s", name, i, got.Type, e.Type)
			}
			obj := got.Object
			if co, ok := obj.(runtime.CacheableObject); ok {
				obj = co.GetObject()
			}
			raw, ok := obj.(*rawobject.Object)
			if !ok {
				t.Fatalf("%s: event %d carries a %T, expected a serialized object", name, i, obj)
			}
			if raw.GetResourceVersion() != e.Pod.ResourceVersion {
				t.Errorf("%s: event %d has resourceVersion %s, expected %s", name, i, raw.GetResourceVersion(), e.Pod.ResourceVersion)
			}
			// Encode what the watcher was given, the way a watch handler would.
			gotBytes, err := runtime.Encode(codec, got.Object)
			if err != nil {
				t.Fatal(err)
			}
			wantBytes, err := runtime.Encode(codec, e.Pod)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotBytes, wantBytes) {
				t.Errorf("%s: event %d encodes differently than the pod it stands for", name, i)
			}
		}
	}
	expect("label watcher", byLabel, []event{{watch.Added, relabeled}, {watch.Modified, moved}, {watch.Deleted, gone}})
	expect("node watcher", byNode, []event{{watch.Added, created}, {watch.Modified, relabeled}, {watch.Deleted, movedAway}})
	// A watcher that starts late is served from the event history rather than from live dispatch.
	expect("late watcher", startWatch("", "", listed.ResourceVersion), []event{{watch.Added, created}, {watch.Modified, relabeled}, {watch.Modified, moved}, {watch.Deleted, gone}})

	stats := rawobject.ReadStats()
	if kept := stats.Created - before.Created; kept != 3 {
		t.Errorf("%d objects were kept serialized, expected the 3 written while watching", kept)
	}
	if stats.PassedThrough == before.PassedThrough {
		t.Errorf("nothing was encoded from stored bytes")
	}
	if n := stats.Decoded - before.Decoded; n != 0 {
		t.Errorf("%d objects were decoded while only being watched", n)
	}

	// Reads through the cache need pods, and the cache now holds a serialized one.
	updated := &corev1.Pod{}
	if err := store.GuaranteedUpdate(ctx, "/pods/ns/listed", updated, false, nil, storage.SimpleUpdate(func(obj runtime.Object) (runtime.Object, error) {
		pod := obj.(*corev1.Pod).DeepCopy()
		pod.Labels = map[string]string{"app": "c"}
		return pod, nil
	}), nil); err != nil {
		t.Fatal(err)
	}
	got := &corev1.Pod{}
	if err := cacher.Get(ctx, "/pods/ns/listed", storage.GetOptions{ResourceVersion: updated.ResourceVersion}, got); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(updated, got); diff != "" {
		t.Errorf("Get from cache (-want +got):\n%s", diff)
	}
	for name, p := range map[string]storage.SelectionPredicate{"everything": predicate("", ""), "by label": predicate("c", ""), "by node": predicate("", "node-1")} {
		list := &corev1.PodList{}
		if err := cacher.GetList(ctx, "/pods/ns/", storage.ListOptions{ResourceVersion: "0", Recursive: true, Predicate: p}, list); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]corev1.Pod{*updated}, list.Items); diff != "" {
			t.Errorf("GetList %s from cache (-want +got):\n%s", name, diff)
		}
	}
	if n := rawobject.ReadStats().Decoded - stats.Decoded; n != 1 {
		t.Errorf("the pod was decoded %d times by one Get and three GetLists, expected once", n)
	}
}
