/*
Copyright 2019 The Kubernetes Authors.

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

package apply

import (
	"context"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/cli-runtime/pkg/printers"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/metadata"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

type applysetPruner struct {
	// mapper meta.RESTMapper

	dynamicClient  dynamic.Interface
	metadataClient metadata.Interface

	visitedUids sets.String
	//visitedNamespaces sets.String
	// labelSelector     string
	// fieldSelector string

	// resources  []*meta.RESTMapping
	// namespaces []string

	cascadingStrategy metav1.DeletionPropagation
	dryRunStrategy    cmdutil.DryRunStrategy
	gracePeriod       int

	toPrinter func(string) (printers.ResourcePrinter, error)

	out io.Writer
}

func newApplysetPruner(o *ApplyOptions) *applysetPruner {
	return &applysetPruner{
		// mapper:        o.Mapper,
		dynamicClient:  o.DynamicClient,
		metadataClient: o.MetadataClient,
		// labelSelector:     o.Selector,
		visitedUids: o.VisitedUids,
		// visitedNamespaces: o.VisitedNamespaces,

		cascadingStrategy: o.DeleteOptions.CascadingStrategy,
		dryRunStrategy:    o.DryRunStrategy,
		gracePeriod:       o.DeleteOptions.GracePeriod,

		toPrinter: o.ToPrinter,

		out: o.Out,
	}
}

func (p *applysetPruner) pruneAll(ctx context.Context, applyset *ApplySet) error {
	applysetLabelSelector := applyset.LabelSelectorForMembers()

	opt := metav1.ListOptions{
		LabelSelector: applysetLabelSelector,
	}

	// TODO: Split into discovery and deletion, run discovery in parallel (and maybe in consistent order or in parallel?)
	for _, restMapping := range applyset.AllPrunableResources() {
		switch restMapping.Scope.Name() {
		case meta.RESTScopeNameNamespace:
			for _, namespace := range applyset.AllPrunableNamespaces() {
				if err := p.prune(ctx, namespace, restMapping, opt); err != nil {
					return fmt.Errorf("error pruning namespaced object %v: %w", restMapping.GroupVersionKind, err)
				}
			}

		case meta.RESTScopeNameRoot:
			if err := p.prune(ctx, metav1.NamespaceNone, restMapping, opt); err != nil {
				return fmt.Errorf("error pruning nonNamespaced object %v: %w", restMapping.GroupVersionKind, err)
			}

		default:
			return fmt.Errorf("unhandled scope %q", restMapping.Scope.Name())
		}
	}
	// namespacedRESTMappings, nonNamespacedRESTMappings, err := prune.GetRESTMappings(o.Mapper, o.PruneResources, o.Namespace != "")
	// if err != nil {
	// 	return fmt.Errorf("error retrieving RESTMappings to prune: %w", err)
	// }

	// for n := range p.visitedNamespaces {
	// 	for _, m := range namespacedRESTMappings {
	// 		if err := p.prune(ctx, n, m, opt); err != nil {
	// 			return fmt.Errorf("error pruning namespaced object %v: %w", m.GroupVersionKind, err)
	// 		}
	// 	}
	// }

	// for _, m := range nonNamespacedRESTMappings {
	// 	if err := p.prune(ctx, metav1.NamespaceNone, m, opt); err != nil {
	// 		return fmt.Errorf("error pruning nonNamespaced object %v: %w", m.GroupVersionKind, err)
	// 	}
	// }

	return nil
}

func (p *applysetPruner) prune(ctx context.Context, namespace string, mapping *meta.RESTMapping, opt metav1.ListOptions) error {
	objects, err := p.metadataClient.Resource(mapping.Resource).Namespace(namespace).List(ctx, opt)
	if err != nil {
		return err
	}

	for i := range objects.Items {
		obj := &objects.Items[i]

		annotations := obj.GetAnnotations()
		if _, ok := annotations[corev1.LastAppliedConfigAnnotation]; !ok {
			// don't prune resources not created with apply
			continue
		}
		uid := obj.GetUID()
		if p.visitedUids.Has(string(uid)) {
			continue
		}
		name := obj.GetName()
		if p.dryRunStrategy != cmdutil.DryRunClient {
			if err := p.delete(ctx, namespace, name, mapping); err != nil {
				return err
			}
		}

		printer, err := p.toPrinter("pruned")
		if err != nil {
			return err
		}
		printer.PrintObj(obj, p.out)
	}
	return nil
}

func (p *applysetPruner) delete(ctx context.Context, namespace, name string, mapping *meta.RESTMapping) error {
	return runDelete(ctx, namespace, name, mapping, p.dynamicClient, p.cascadingStrategy, p.gracePeriod, p.dryRunStrategy == cmdutil.DryRunServer)
}

// func runDelete(namespace, name string, mapping *meta.RESTMapping, c dynamic.Interface, cascadingStrategy metav1.DeletionPropagation, gracePeriod int, serverDryRun bool) error {
// 	options := asDeleteOptions(cascadingStrategy, gracePeriod)
// 	if serverDryRun {
// 		options.DryRun = []string{metav1.DryRunAll}
// 	}
// 	return c.Resource(mapping.Resource).Namespace(namespace).Delete(context.TODO(), name, options)
// }

// func asDeleteOptions(cascadingStrategy metav1.DeletionPropagation, gracePeriod int) metav1.DeleteOptions {
// 	options := metav1.DeleteOptions{}
// 	if gracePeriod >= 0 {
// 		options = *metav1.NewDeleteOptions(int64(gracePeriod))
// 	}
// 	options.PropagationPolicy = &cascadingStrategy
// 	return options
// }
