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
	"strconv"

	apiv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/protopluck"
	"k8s.io/apiserver/pkg/storage/rawobject"
)

// RawWatchObjects describes how to serve pod watches without decoding pods.
func RawWatchObjects() *rawobject.Config {
	return &rawobject.Config{
		GroupVersionKind: apiv1.SchemeGroupVersion.WithKind("Pod"),
		AttrFunc:         rawAttrs,
	}
}

// Field numbers of v1.Pod and the messages it embeds, see
// staging/src/k8s.io/api/core/v1/generated.proto.
const (
	podSpecField   = 2
	podStatusField = 3
)

// The paths below are everything GetAttrs reads from a pod. Knowing the list
// up front is what makes it possible to skip decoding the rest.
const (
	rawName = iota
	rawNamespace
	rawLabels
	rawNodeName
	rawRestartPolicy
	rawSchedulerName
	rawServiceAccountName
	rawHostNetwork
	rawPhase
	rawPodIP
	rawPodIPs
	rawNominatedNodeName
)

var rawAttrsPlucker = protopluck.MustCompile(
	rawobject.NamePath,
	rawobject.NamespacePath,
	rawobject.LabelsPath,
	protopluck.Path{podSpecField, 10},
	protopluck.Path{podSpecField, 3},
	protopluck.Path{podSpecField, 19},
	protopluck.Path{podSpecField, 8},
	protopluck.Path{podSpecField, 11},
	protopluck.Path{podStatusField, 1},
	protopluck.Path{podStatusField, 6},
	protopluck.Path{podStatusField, 12, 1},
	protopluck.Path{podStatusField, 11},
)

// rawAttrs is GetAttrs for a protobuf encoded v1.Pod. Like GetAttrs, it sees
// the pod as it reads back from storage, which is why it reproduces the one
// read-time default that selectable fields depend on: podIPs from podIP.
func rawAttrs(msg []byte) (rawobject.Attrs, error) {
	var buf [24]protopluck.Value
	values, err := rawAttrsPlucker.Pluck(msg, buf[:0])
	if err != nil {
		return rawobject.Attrs{}, err
	}

	var meta rawobject.ObjectMetaAttrs
	var nodeName, restartPolicy, schedulerName, serviceAccountName, phase, podIP, firstPodIP, nominatedNodeName []byte
	var hostNetwork, sawPodIPs bool
	for _, v := range values {
		switch v.Index {
		case rawName:
			meta.SetName(v)
		case rawNamespace:
			meta.SetNamespace(v)
		case rawLabels:
			if err := meta.AddLabel(v); err != nil {
				return rawobject.Attrs{}, err
			}
		case rawNodeName:
			nodeName = v.Bytes
		case rawRestartPolicy:
			restartPolicy = v.Bytes
		case rawSchedulerName:
			schedulerName = v.Bytes
		case rawServiceAccountName:
			serviceAccountName = v.Bytes
		case rawHostNetwork:
			hostNetwork = v.Bool()
		case rawPhase:
			phase = v.Bytes
		case rawPodIP:
			podIP = v.Bytes
		case rawPodIPs:
			if !sawPodIPs {
				sawPodIPs, firstPodIP = true, v.Bytes
			}
		case rawNominatedNodeName:
			nominatedNodeName = v.Bytes
		}
	}
	if !sawPodIPs {
		firstPodIP = podIP
	}

	attrs := meta.Attrs()
	attrs.Fields = fields.Set{
		"metadata.name":            attrs.Name,
		"metadata.namespace":       attrs.Namespace,
		"spec.nodeName":            string(nodeName),
		"spec.restartPolicy":       string(restartPolicy),
		"spec.schedulerName":       string(schedulerName),
		"spec.serviceAccountName":  string(serviceAccountName),
		"spec.hostNetwork":         strconv.FormatBool(hostNetwork),
		"status.phase":             string(phase),
		"status.podIP":             string(firstPodIP),
		"status.nominatedNodeName": string(nominatedNodeName),
	}
	return attrs, nil
}
