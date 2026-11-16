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

package etcd3

import (
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
	"k8s.io/apiserver/pkg/storage/rawobject"
	storagetesting "k8s.io/apiserver/pkg/storage/testing"
)

// TestWatchRawObjects watches etcd directly, with a selector, on a store that
// keeps objects serialized. Filtering then runs on plucked attributes, of the
// previous state of the object as well as of the current one.
func TestWatchRawObjects(t *testing.T) {
	config := storagetesting.StoreConfigForBenchmarks()
	ctx, store, _ := testSetup(t, withCodec(config.Codec), func(o *setupOptions) {
		o.newFunc, o.newListFunc = config.NewFunc, config.NewListFunc
	})
	store.SetRawWatchObjects(storagetesting.RawWatchObjectsForBenchmarks())
	ctx, cancel := context.WithTimeout(ctx, wait.ForeverTestTimeout)
	defer cancel()

	pod := func(app string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod", Labels: map[string]string{"app": app}},
			Spec:       corev1.PodSpec{NodeName: "node", Containers: []corev1.Container{{Name: "c"}}},
		}
	}
	update := func(app, note string) *corev1.Pod {
		out := &corev1.Pod{}
		if err := store.GuaranteedUpdate(ctx, "/pods/ns/pod", out, false, nil, storage.SimpleUpdate(func(obj runtime.Object) (runtime.Object, error) {
			updated := obj.(*corev1.Pod).DeepCopy()
			updated.Labels["app"] = app
			updated.Annotations = map[string]string{"note": note}
			return updated, nil
		}), nil); err != nil {
			t.Fatal(err)
		}
		return out
	}

	list := &corev1.PodList{}
	if err := store.GetList(ctx, "/pods/", storage.ListOptions{Recursive: true, Predicate: storage.Everything}, list); err != nil {
		t.Fatal(err)
	}
	w, err := store.Watch(ctx, "/pods/", storage.ListOptions{
		ResourceVersion: list.ResourceVersion,
		Recursive:       true,
		Predicate: storage.SelectionPredicate{
			Label:    labels.SelectorFromSet(labels.Set{"app": "watched"}),
			Field:    fields.OneTermEqualSelector("spec.nodeName", "node"),
			GetAttrs: config.GetAttrsFunc,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	created := &corev1.Pod{}
	if err := store.Create(ctx, "/pods/ns/pod", pod("ignored"), created, 0); err != nil {
		t.Fatal(err)
	}
	selected := update("watched", "selected")
	touched := update("watched", "still selected")
	unselected := update("ignored", "no longer selected")
	reselected := update("watched", "selected again")
	deleted := &corev1.Pod{}
	if err := store.Delete(ctx, "/pods/ns/pod", deleted, nil, storage.ValidateAllObjectFunc, nil, storage.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}

	// A pod leaves the selection in its last selected state, at the revision it left.
	left := touched.DeepCopy()
	left.ResourceVersion = unselected.ResourceVersion
	gone := reselected.DeepCopy()
	gone.ResourceVersion = deleted.ResourceVersion

	for i, want := range []struct {
		Type watch.EventType
		Pod  *corev1.Pod
	}{
		{watch.Added, selected},
		{watch.Modified, touched},
		{watch.Deleted, left},
		{watch.Added, reselected},
		{watch.Deleted, gone},
	} {
		var got watch.Event
		select {
		case got = <-w.ResultChan():
		case <-ctx.Done():
			t.Fatalf("timed out waiting for event %d", i)
		}
		if got.Type != want.Type {
			t.Fatalf("event %d is %s, expected %s", i, got.Type, want.Type)
		}
		raw, ok := got.Object.(*rawobject.Object)
		if !ok {
			t.Fatalf("event %d carries a %T, expected a serialized object", i, got.Object)
		}
		if raw.GetResourceVersion() != want.Pod.ResourceVersion {
			t.Errorf("event %d has resourceVersion %s, expected %s", i, raw.GetResourceVersion(), want.Pod.ResourceVersion)
		}
		decoded, err := raw.DecodedObject()
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(want.Pod, decoded); diff != "" {
			t.Errorf("event %d (-want +got):\n%s", i, diff)
		}
	}
}
