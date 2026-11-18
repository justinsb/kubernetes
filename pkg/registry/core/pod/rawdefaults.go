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

	"k8s.io/apimachinery/pkg/util/protopluck"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/kubernetes/pkg/features"
)

// This file decides whether a protobuf encoded v1.Pod is already in the state
// defaulting would leave it in, without decoding it. A pod that is can be
// served from its stored bytes. One that is not, because it was written
// before a default existed or by an apiserver configured differently, has to
// take the decoding path so that the default gets applied.
//
// The checks do not reimplement defaulting, they verify what defaulting
// guarantees: that a field is set, or that two fields agree. They only need
// to tell apart states an apiserver could have stored, so anything unusual is
// reported as needing defaulting rather than analyzed. Being wrong in that
// direction costs a decode. Being wrong in the other direction is caught by
// TestRawPodDefaultingDetection, which fails when a default is added to
// pkg/apis/core/v1 without a check here.
//
// Field numbers are those of staging/src/k8s.io/api/core/v1/generated.proto.

// podDefaults captures the feature gates that defaulting of pods depends on.
type podDefaults struct {
	// httpProbeProtocol is set if httpGet actions get a default protocol.
	httpProbeProtocol bool
	// podLevelResources is set if pod-level resources are defaulted on read.
	podLevelResources bool
}

func currentPodDefaults() podDefaults {
	return podDefaults{
		httpProbeProtocol: utilfeature.DefaultFeatureGate.Enabled(features.H2CContainerProbe),
		podLevelResources: utilfeature.DefaultFeatureGate.Enabled(features.PodLevelResources) &&
			!utilfeature.DefaultFeatureGate.Enabled(features.PodLevelResourcesFixDefaulting),
	}
}

// isDefaulted reports whether defaulting would leave the pod unchanged.
func (d podDefaults) isDefaulted(pod []byte) bool {
	if d.podLevelResources {
		// Derived from every container, and on its way out: not worth a check.
		return false
	}
	var spec, status []byte
	ok := protopluck.Range(pod, func(num int32, v protopluck.Value) bool {
		switch num {
		case 2:
			// A message split in several chunks is legal, and nothing writes it.
			if spec != nil {
				return false
			}
			spec = v.Bytes
		case 3:
			if status != nil {
				return false
			}
			status = v.Bytes
		}
		return true
	})
	return ok && d.specIsDefaulted(spec) && d.statusIsDefaulted(status)
}

func (d podDefaults) specIsDefaulted(spec []byte) bool {
	// Scalars first: what containers need checking depends on hostNetwork,
	// which comes after them on the wire.
	var restartPolicy, dnsPolicy, schedulerName, serviceAccountName, serviceAccount []byte
	var hasGracePeriod, hasSecurityContext, hasEnableServiceLinks, hostNetwork bool
	ok := protopluck.Range(spec, func(num int32, v protopluck.Value) bool {
		switch num {
		case 3:
			restartPolicy = v.Bytes
		case 4:
			// Negative values are replaced. They show up as huge varints.
			hasGracePeriod = int64(v.Num) >= 0
		case 6:
			dnsPolicy = v.Bytes
		case 8:
			serviceAccountName = v.Bytes
		case 9:
			serviceAccount = v.Bytes
		case 11:
			hostNetwork = v.Bool()
		case 14:
			hasSecurityContext = true
		case 19:
			schedulerName = v.Bytes
		case 30:
			hasEnableServiceLinks = true
		case 32:
			return quantityEntryIsDefaulted(v, nil)
		case 40:
			return resourcesAreDefaulted(v.Bytes, false)
		}
		return true
	})
	if !ok || len(restartPolicy) == 0 || len(dnsPolicy) == 0 || len(schedulerName) == 0 ||
		!hasGracePeriod || !hasSecurityContext || !hasEnableServiceLinks ||
		// serviceAccount is an alias kept equal to serviceAccountName.
		!bytes.Equal(serviceAccountName, serviceAccount) {
		return false
	}

	return protopluck.Range(spec, func(num int32, v protopluck.Value) bool {
		switch num {
		case 1:
			return volumeIsDefaulted(v.Bytes)
		case 2, 20:
			return d.containerIsDefaulted(v.Bytes, hostNetwork, true)
		case 34:
			// An ephemeral container wraps what it has in common with a container.
			return protopluck.Range(v.Bytes, func(num int32, v protopluck.Value) bool {
				return num != 1 || d.containerIsDefaulted(v.Bytes, false, false)
			})
		}
		return true
	})
}

// containerIsDefaulted checks a Container or an EphemeralContainerCommon,
// which share their field numbers. hostPorts and requests enable the checks
// for the two defaults that only regular and init containers get: host ports
// under hostNetwork, and requests from limits.
func (d podDefaults) containerIsDefaulted(container []byte, hostPorts, requests bool) bool {
	var imagePullPolicy, terminationMessagePath, terminationMessagePolicy []byte
	ok := protopluck.Range(container, func(num int32, v protopluck.Value) bool {
		switch num {
		case 6:
			var protocol []byte
			var hostPort uint64
			return protopluck.Range(v.Bytes, func(num int32, v protopluck.Value) bool {
				switch num {
				case 2:
					hostPort = v.Num
				case 4:
					protocol = v.Bytes
				}
				return true
			}) && len(protocol) > 0 && (!hostPorts || hostPort != 0)
		case 7:
			return envVarIsDefaulted(v.Bytes)
		case 8:
			return resourcesAreDefaulted(v.Bytes, requests)
		case 10, 11, 22:
			return d.probeIsDefaulted(v.Bytes)
		case 12:
			// postStart and preStop
			return protopluck.Range(v.Bytes, func(num int32, v protopluck.Value) bool {
				if num != 1 && num != 2 {
					return true
				}
				return protopluck.Range(v.Bytes, func(num int32, v protopluck.Value) bool {
					return num != 2 || d.httpGetIsDefaulted(v.Bytes)
				})
			})
		case 13:
			terminationMessagePath = v.Bytes
		case 14:
			imagePullPolicy = v.Bytes
		case 20:
			terminationMessagePolicy = v.Bytes
		}
		return true
	})
	return ok && len(imagePullPolicy) > 0 && len(terminationMessagePath) > 0 && len(terminationMessagePolicy) > 0
}

func envVarIsDefaulted(envVar []byte) bool {
	return protopluck.Range(envVar, func(num int32, v protopluck.Value) bool {
		if num != 3 { // valueFrom
			return true
		}
		return protopluck.Range(v.Bytes, func(num int32, v protopluck.Value) bool {
			switch num {
			case 1:
				return fieldRefIsDefaulted(v.Bytes)
			case 5:
				return hasField(v.Bytes, 4) // fileKeyRef.optional
			}
			return true
		})
	})
}

func fieldRefIsDefaulted(fieldRef []byte) bool {
	var apiVersion []byte
	return protopluck.Range(fieldRef, func(num int32, v protopluck.Value) bool {
		if num == 1 {
			apiVersion = v.Bytes
		}
		return true
	}) && len(apiVersion) > 0
}

func hasField(msg []byte, field int32) bool {
	found := false
	return protopluck.Range(msg, func(num int32, v protopluck.Value) bool {
		found = found || num == field
		return true
	}) && found
}

func (d podDefaults) probeIsDefaulted(probe []byte) bool {
	var timeout, period, successThreshold, failureThreshold uint64
	return protopluck.Range(probe, func(num int32, v protopluck.Value) bool {
		switch num {
		case 1:
			return protopluck.Range(v.Bytes, func(num int32, v protopluck.Value) bool {
				switch num {
				case 2:
					return d.httpGetIsDefaulted(v.Bytes)
				case 4:
					return hasField(v.Bytes, 2) // grpc.service
				}
				return true
			})
		case 3:
			timeout = v.Num
		case 4:
			period = v.Num
		case 5:
			successThreshold = v.Num
		case 6:
			failureThreshold = v.Num
		}
		return true
	}) && timeout != 0 && period != 0 && successThreshold != 0 && failureThreshold != 0
}

func (d podDefaults) httpGetIsDefaulted(httpGet []byte) bool {
	var path, scheme []byte
	hasProtocol := false
	return protopluck.Range(httpGet, func(num int32, v protopluck.Value) bool {
		switch num {
		case 1:
			path = v.Bytes
		case 4:
			scheme = v.Bytes
		case 6:
			hasProtocol = true
		}
		return true
	}) && len(path) > 0 && len(scheme) > 0 && (hasProtocol || !d.httpProbeProtocol)
}

// resourcesAreDefaulted checks a ResourceRequirements: its quantities, and if
// requests is set, that every limit has a request, as requests default to
// limits.
func resourcesAreDefaulted(resources []byte, requests bool) bool {
	var limited, requested resourceNames
	ok := protopluck.Range(resources, func(num int32, v protopluck.Value) bool {
		switch num {
		case 1:
			return quantityEntryIsDefaulted(v, &limited)
		case 2:
			return quantityEntryIsDefaulted(v, &requested)
		}
		return true
	})
	if !ok || !requests {
		return ok
	}
	for _, name := range limited.names[:limited.n] {
		if !requested.has(name) {
			return false
		}
	}
	return true
}

// resourceNames is a small set of resource names that does not allocate. A
// container with more resources than it holds is left to the decoder.
type resourceNames struct {
	names [8][]byte
	n     int
}

func (r *resourceNames) add(name []byte) bool {
	if r.n == len(r.names) {
		return false
	}
	r.names[r.n] = name
	r.n++
	return true
}

func (r *resourceNames) has(name []byte) bool {
	for _, n := range r.names[:r.n] {
		if bytes.Equal(n, name) {
			return true
		}
	}
	return false
}

// quantityEntryIsDefaulted checks an entry of a ResourceList, and records its
// name if asked to. Defaulting rounds quantities up to the milli scale.
func quantityEntryIsDefaulted(v protopluck.Value, names *resourceNames) bool {
	name, quantity, err := v.MapEntry()
	if err != nil || (names != nil && !names.add(name)) {
		return false
	}
	var s []byte
	return protopluck.Range(quantity, func(num int32, v protopluck.Value) bool {
		if num == 1 {
			s = v.Bytes
		}
		return true
	}) && isRoundQuantity(s)
}

// isRoundQuantity recognizes the quantities that obviously need no rounding:
// an integer, optionally followed by a suffix no finer than milli. Such as
// "2", "500m" or "64Mi". The few that are written any other way are not worth
// parsing here.
func isRoundQuantity(s []byte) bool {
	digits := 0
	for digits < len(s) && s[digits] >= '0' && s[digits] <= '9' {
		digits++
	}
	if digits == 0 {
		return false
	}
	switch string(s[digits:]) {
	case "", "m", "k", "M", "G", "T", "P", "E", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei":
		return true
	}
	return false
}

// volumeIsDefaulted checks a Volume. It knows the volume sources pods
// commonly use, and leaves pods with any other to the decoder.
func volumeIsDefaulted(volume []byte) bool {
	sources := 0
	return protopluck.Range(volume, func(num int32, v protopluck.Value) bool {
		if num != 2 { // volumeSource
			return true
		}
		return protopluck.Range(v.Bytes, func(num int32, v protopluck.Value) bool {
			sources++
			switch num {
			case 2, 7, 10, 28: // emptyDir, nfs, persistentVolumeClaim, csi: nothing to default
				return true
			case 1: // hostPath
				return hasField(v.Bytes, 2) // type
			case 6, 19: // secret, configMap
				return hasField(v.Bytes, 3) // defaultMode
			case 16: // downwardAPI
				return hasField(v.Bytes, 2) && downwardAPIItemsAreDefaulted(v.Bytes) // defaultMode
			case 26: // projected
				return hasField(v.Bytes, 2) && protopluck.Range(v.Bytes, func(num int32, v protopluck.Value) bool { // defaultMode
					if num != 1 { // sources
						return true
					}
					return protopluck.Range(v.Bytes, func(num int32, v protopluck.Value) bool {
						switch num {
						case 1, 3: // secret, configMap
							return true
						case 2: // downwardAPI
							return downwardAPIItemsAreDefaulted(v.Bytes)
						case 4: // serviceAccountToken
							return hasField(v.Bytes, 2) // expirationSeconds
						}
						return false
					})
				})
			}
			return false
		})
		// A volume without a source becomes an emptyDir.
	}) && sources > 0
}

// downwardAPIItemsAreDefaulted checks the items of a DownwardAPIVolumeSource
// or a DownwardAPIProjection, which both keep them in field 1.
func downwardAPIItemsAreDefaulted(downwardAPI []byte) bool {
	return protopluck.Range(downwardAPI, func(num int32, v protopluck.Value) bool {
		if num != 1 {
			return true
		}
		return protopluck.Range(v.Bytes, func(num int32, v protopluck.Value) bool {
			return num != 2 || fieldRefIsDefaulted(v.Bytes)
		})
	})
}

func (d podDefaults) statusIsDefaulted(status []byte) bool {
	var podIP, firstPodIP []byte
	hasPodIPs := false
	ok := protopluck.Range(status, func(num int32, v protopluck.Value) bool {
		switch num {
		case 6:
			podIP = v.Bytes
		case 12:
			if hasPodIPs {
				return true
			}
			hasPodIPs = true
			return protopluck.Range(v.Bytes, func(num int32, v protopluck.Value) bool {
				if num == 1 {
					firstPodIP = v.Bytes
				}
				return true
			})
		case 8, 10, 13: // statuses of containers, init containers, ephemeral containers
			return protopluck.Range(v.Bytes, func(num int32, v protopluck.Value) bool {
				switch num {
				case 10:
					return quantityEntryIsDefaulted(v, nil)
				case 11:
					return resourcesAreDefaulted(v.Bytes, false)
				}
				return true
			})
		case 19:
			return quantityEntryIsDefaulted(v, nil)
		case 20:
			return resourcesAreDefaulted(v.Bytes, false)
		}
		return true
	})
	// podIP is kept equal to the first of podIPs.
	return ok && bytes.Equal(podIP, firstPodIP)
}
