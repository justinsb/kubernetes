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
	"fmt"
	"time"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/client"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/kubectl"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/labels"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/util"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ReplicationController", func() {
	var c *client.Client

	BeforeEach(func() {
		var err error
		c, err = loadClient()
		Expect(err).NotTo(HaveOccurred())
	})

	It("should serve a basic image on each replica with a public image", func() {
		ServeImageOrFail(c, "basic", "kubernetes/serve_hostname:1.1")
	})

	It("should serve a basic image on each replica with a private image", func() {
		switch testContext.provider {
		case "gce", "gke":
			ServeImageOrFail(c, "private", "gcr.io/_b_k8s_test/serve_hostname:1.0")
		default:
			By(fmt.Sprintf("Skipping private variant, which is only supported for providers gce and gke (not %s)",
				testContext.provider))
		}
	})
})

// Finds the NodeAddress which maximizes scoreFn
func findBest(candidates []api.NodeAddress, scoreFn func(*api.NodeAddress) int) *api.NodeAddress {
	var best *api.NodeAddress
	bestScore := 0

	for i := range candidates {
		score := scoreFn(&candidates[i])
		if best != nil && score < bestScore {
			continue
		}

		best = &candidates[i]
		bestScore = score
	}

	return best
}

// Scoring function to pick a NodeAddress for health-checking
func scoreForHealthCheck(a *api.NodeAddress) int {
	score := 0
	switch a.Type {
	case api.NodeExternalIP:
		score += 4
	case api.NodeHostName:
		score += 3
	case api.NodeLegacyHostIP:
		score += 2
	case api.NodeInternalIP:
		score += 1
	}
	return score
}

func getHealthCheckAddress(node *api.Node) string {
	nodeAddress := findBest(node.Status.Addresses, scoreForHealthCheck)
	if nodeAddress == nil {
		return ""
	}
	return nodeAddress.Address
}

// A basic test to check the deployment of an image using
// a replication controller. The image serves its hostname
// which is checked for each replica.
func ServeImageOrFail(c *client.Client, test string, image string) {
	ns := api.NamespaceDefault
	name := "my-hostname-" + test + "-" + string(util.NewUUID())
	replicas := 2

	// Create a replication controller for a service
	// that serves its hostname.
	// The source for the Docker containter kubernetes/serve_hostname is
	// in contrib/for-demos/serve_hostname
	By(fmt.Sprintf("Creating replication controller %s", name))
	controller, err := c.ReplicationControllers(ns).Create(&api.ReplicationController{
		ObjectMeta: api.ObjectMeta{
			Name: name,
		},
		Spec: api.ReplicationControllerSpec{
			Replicas: replicas,
			Selector: map[string]string{
				"name": name,
			},
			Template: &api.PodTemplateSpec{
				ObjectMeta: api.ObjectMeta{
					Labels: map[string]string{"name": name},
				},
				Spec: api.PodSpec{
					Containers: []api.Container{
						{
							Name:  name,
							Image: image,
							Ports: []api.ContainerPort{{ContainerPort: 9376}},
						},
					},
				},
			},
		},
	})
	Expect(err).NotTo(HaveOccurred())
	// Cleanup the replication controller when we are done.
	defer func() {
		// Resize the replication controller to zero to get rid of pods.
		By("Cleaning up the replication controller")
		rcReaper, err := kubectl.ReaperFor("ReplicationController", c)
		if err != nil {
			Logf("Failed to cleanup replication controller %v: %v.", controller.Name, err)
		}
		if _, err = rcReaper.Stop(ns, controller.Name); err != nil {
			Logf("Failed to stop replication controller %v: %v.", controller.Name, err)
		}
	}()

	// List the pods, making sure we observe all the replicas.
	listTimeout := time.Minute
	label := labels.SelectorFromSet(labels.Set(map[string]string{"name": name}))
	pods, err := c.Pods(ns).List(label)
	Expect(err).NotTo(HaveOccurred())
	t := time.Now()
	for {
		Logf("Controller %s: Found %d pods out of %d", name, len(pods.Items), replicas)
		if len(pods.Items) == replicas {
			break
		}
		if time.Since(t) > listTimeout {
			Failf("Controller %s: Gave up waiting for %d pods to come up after seeing only %d pods after %v seconds",
				name, replicas, len(pods.Items), time.Since(t).Seconds())
		}
		time.Sleep(5 * time.Second)
		pods, err = c.Pods(ns).List(label)
		Expect(err).NotTo(HaveOccurred())
	}

	By("Ensuring each pod is running and has a hostIP")

	// Wait for the pods to enter the running state. Waiting loops until the pods
	// are running so non-running pods cause a timeout for this test.
	for _, pod := range pods.Items {
		err = waitForPodRunning(c, pod.Name)
		Expect(err).NotTo(HaveOccurred())
	}

	// Try to make sure we get a hostIP for each pod.
	hostIPTimeout := 2 * time.Minute
	t = time.Now()
	for i, pod := range pods.Items {
		for {
			p, err := c.Pods(ns).Get(pod.Name)
			Expect(err).NotTo(HaveOccurred())
			if p.Status.HostIP != "" {
				Logf("Controller %s: Replica %d has hostIP: %s", name, i+1, p.Status.HostIP)
				Logf("Controller %s: Replica %d has status: %v", name, i+1, p.Status)
				break
			}
			if time.Since(t) >= hostIPTimeout {
				Failf("Controller %s: Gave up waiting for hostIP of replica %d after %v seconds",
					name, i, time.Since(t).Seconds())
			}
			Logf("Controller %s: Retrying to get the hostIP of replica %d", name, i+1)
			time.Sleep(5 * time.Second)
		}
	}

	// Re-fetch the pod information to update the host port information.
	pods, err = c.Pods(ns).List(label)
	Expect(err).NotTo(HaveOccurred())

	// List the nodes, so we can get the external IP
	By("Fetching node information")
	nodes, err := c.Nodes().List()
	Expect(err).NotTo(HaveOccurred())
	nodeMap := make(map[string]api.Node)
	for _, node := range nodes.Items {
		nodeMap[node.Name] = node
	}

	// Verify that something is listening.
	By("Trying to dial each unique pod")

	for i, pod := range pods.Items {
		body, err := c.Get().
			Prefix("proxy").
			Resource("pods").
			Name(string(pod.Name)).
			Do().
			Raw()
		//		node, found := nodeMap[pod.Status.Host]
		//		Expect(found).To(BeTrue())
		//
		//		Logf("Pod: %s: Found node: %v", pod.Name, node)
		//
		//		hostAddress := getHealthCheckAddress(&node)
		//		Expect(hostAddress).ToNot(BeEmpty())
		//
		//		Logf("Pod: %s: Chose node address: %s", pod.Name, hostAddress)
		//
		//		resp, err := http.Get(fmt.Sprintf("http://%s:8080", hostAddress))

		if err != nil {
			Failf("Controller %s: Failed to GET from replica %d: %v", name, i+1, err)
		}
		// The body should be the pod name.
		if string(body) != pod.Name {
			Failf("Controller %s: Replica %d expected response %s but got %s", name, i+1, pod.Name, string(body))
		}
		Logf("Controller %s: Got expected result from replica %d: %s", name, i+1, string(body))
	}
}
