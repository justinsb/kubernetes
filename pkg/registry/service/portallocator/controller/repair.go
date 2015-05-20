/*
Copyright 2015 The Kubernetes Authors All rights reserved.

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

package controller

import (
	"fmt"
	"time"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/registry/service"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/registry/service/portallocator"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/util"
)

// See ipallocator/controller/repair.go; this is a copy for ports.
type Repair struct {
	interval  time.Duration
	registry  service.Registry
	portRange util.PortRange
	alloc     service.RangeRegistry
}

// NewRepair creates a controller that periodically ensures that all portalIPs are uniquely allocated across the cluster
// and generates informational warnings for a cluster that is not in sync.
func NewRepair(interval time.Duration, registry service.Registry, portRange util.PortRange, alloc service.RangeRegistry) *Repair {
	return &Repair{
		interval:  interval,
		registry:  registry,
		portRange: portRange,
		alloc:     alloc,
	}
}

// RunUntil starts the controller until the provided ch is closed.
func (c *Repair) RunUntil(ch chan struct{}) {
	util.Until(func() {
		if err := c.RunOnce(); err != nil {
			util.HandleError(err)
		}
	}, c.interval, ch)
}

// RunOnce verifies the state of the portal IP allocations and returns an error if an unrecoverable problem occurs.
func (c *Repair) RunOnce() error {
	// TODO: (per smarterclayton) if Get() or ListServices() is a weak consistency read,
	// or if they are executed against different leaders,
	// the ordering guarantee required to ensure no IP is allocated twice is violated.
	// ListServices must return a ResourceVersion higher than the etcd index Get triggers,
	// and the release code must not release services that have had IPs allocated but not yet been created
	// See #8295

	latest, err := c.alloc.Get()
	if err != nil {
		return fmt.Errorf("unable to refresh the port block: %v", err)
	}

	ctx := api.WithNamespace(api.NewDefaultContext(), api.NamespaceAll)
	list, err := c.registry.ListServices(ctx)
	if err != nil {
		return fmt.Errorf("unable to refresh the port block: %v", err)
	}

	r := portallocator.NewPortAllocator(c.portRange)
	for _, svc := range list.Items {
		ports := []int{}

		// TODO(justinsb): Collect NodePorts
		if len(ports) == 0 {
			continue
		}

		for _, port := range ports {
			switch err := r.Allocate(port); err {
			case nil:
			case portallocator.ErrAllocated:
				// TODO: send event
				// portal IP is broken, reallocate
				util.HandleError(fmt.Errorf("the port %d for service %s/%s was assigned to multiple services; please recreate", port, svc.Name, svc.Namespace))
			case portallocator.ErrNotInRange:
				// TODO: send event
				// portal IP is broken, reallocate
				util.HandleError(fmt.Errorf("the port %d for service %s/%s is not within the port range %v; please recreate", port, svc.Name, svc.Namespace, c.portRange))
			case portallocator.ErrFull:
				// TODO: send event
				return fmt.Errorf("the port range %v is full; you must widen the port range in order to create new services", c.portRange)
			default:
				return fmt.Errorf("unable to allocate port %d for service %s/%s due to an unknown error, exiting: %v", port, svc.Name, svc.Namespace, err)
			}
		}
	}

	err = r.Snapshot(latest)
	if err != nil {
		return fmt.Errorf("unable to persist the updated port allocations: %v", err)
	}

	if err := c.alloc.CreateOrUpdate(latest); err != nil {
		return fmt.Errorf("unable to persist the updated port allocations: %v", err)
	}
	return nil
}
