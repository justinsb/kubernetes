package apply

import (
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ApplySet tracks the information about an applyset apply/prune
type ApplySet struct {
	// ID is the label value that we are using to identify this applyset.
	ID string

	// resources is the set of all the resources that (might) be part of this applyset.
	resources map[schema.GroupVersionResource]*meta.RESTMapping

	// namespaces is the set of all namespaces that (might) contain objects that are part of this applyset.
	namespaces map[string]struct{}
}

func NewApplySet(id string) *ApplySet {
	return &ApplySet{
		ID:         id,
		resources:  make(map[schema.GroupVersionResource]*meta.RESTMapping),
		namespaces: make(map[string]struct{}),
	}
}

func (a *ApplySet) LabelsForMember() map[string]string {
	return map[string]string{
		"applyset.k8s.io/part-of": a.ID,
	}
}

func (a *ApplySet) LabelSelectorForMembers() string {
	return metav1.FormatLabelSelector(&metav1.LabelSelector{
		MatchLabels: a.LabelsForMember(),
	})
}

func (a *ApplySet) MarkObjectApplied(resource *meta.RESTMapping, namespace string) {
	a.resources[resource.Resource] = resource
	if namespace != "" {
		a.namespaces[namespace] = struct{}{}
	}
}

// AllPrunableResources returns the list of all resources that should be considered for pruning.
// This is potentially a superset of the resources that actually contain resources.
func (a *ApplySet) AllPrunableResources() []*meta.RESTMapping {
	var ret []*meta.RESTMapping
	for _, m := range a.resources {
		ret = append(ret, m)
	}
	return ret
}

// AllPrunableNamespaces returns the list of all namespaces that should be considered for pruning.
// This is potentially a superset of the namespaces that actually contain resources.
func (a *ApplySet) AllPrunableNamespaces() []string {
	var ret []string
	for ns := range a.namespaces {
		ret = append(ret, ns)
	}
	return ret
}
