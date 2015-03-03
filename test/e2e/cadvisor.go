/*
Copyright 2015 Google Inc. All rights reserved.

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

package e2e

import (
	"errors"
	"fmt"
	"time"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/client"

	. "github.com/onsi/ginkgo"
)

const (
	timeout       = 1 * time.Minute
	maxRetries    = 10
	sleepDuration = time.Minute
)

var _ = Describe("Cadvisor", func() {
	var c *client.Client

	BeforeEach(func() {
		var err error
		c, err = loadClient()
		expectNoError(err)
	})

	It("should be healthy on every node.", func() {
		CheckCadvisorHealthOnAllNodes(c, 5*time.Minute)
	})
})

func CheckCadvisorHealthOnAllNodes(c *client.Client, timeout time.Duration) {
	By("getting list of nodes")
	nodeList, err := c.Nodes().List()
	expectNoError(err)
	var errs []error
	retries := maxRetries
	for {
		errs = []error{}
		for _, node := range nodeList.Items {
			// cadvisor is not accessible directly unless its port (4194 by default) is exposed.
			// Here, we access '/stats/' REST endpoint on the kubelet which polls cadvisor internally.

			By(fmt.Sprintf("Node status %v", node.Status))
			addresses := node.Status.InternalAddresses()
			if len(addresses) == 0 {
				errs = append(errs, errors.New("Cannot determine internal IP"))
				continue
			}
			statsResource := fmt.Sprintf("api/v1beta1/proxy/minions/%s/stats/", addresses[0].Value)
			By(fmt.Sprintf("Querying stats from node %s using url %s", addresses[0].Value, statsResource))
			_, err = c.Get().AbsPath(statsResource).Timeout(timeout).Do().Raw()
			if err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) == 0 {
			return
		}
		if retries--; retries <= 0 {
			break
		}
		Logf("failed to retrieve kubelet stats -\n %v", errs)
		time.Sleep(sleepDuration)
	}
	Failf("Failed after retrying %d times for cadvisor to be healthy on all nodes. Errors:\n%v", maxRetries, errs)
}
