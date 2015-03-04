/*
Copyright 2014 Google Inc. All rights reserved.

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

package aws_cloud

import (
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"

	"code.google.com/p/gcfg"
	"github.com/golang/glog"
	"github.com/mitchellh/goamz/aws"
	"github.com/mitchellh/goamz/ec2"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/cloudprovider"
)

type EC2 interface {
	Instances(instIds []string, filter *ec2.Filter) (resp *ec2.InstancesResp, err error)
}

// AWSCloud is an implementation of Interface, TCPLoadBalancer and Instances for Amazon Web Services.
type AWSCloud struct {
	ec2 EC2
	cfg *AWSCloudConfig
}

type AWSCloudConfig struct {
	Global struct {
		Region    string
		AccessKey string
		SecretKey string
	}
}

type AuthFunc func(config *AWSCloudConfig) (auth aws.Auth, err error)

func init() {
	cloudprovider.RegisterCloudProvider("aws", func(config io.Reader) (cloudprovider.Interface, error) {
		return newAWSCloud(config, getAuth)
	})
}

func getAuth(config *AWSCloudConfig) (auth aws.Auth, err error) {
	// If empty strings are passed to GetAuth, it will look for
	// environment variables and instance based role credentials.
	accessKey := ""
	secretKey := ""

	if config != nil {
		accessKey = config.Global.AccessKey
		secretKey = config.Global.SecretKey
	}

	return aws.GetAuth(accessKey, secretKey)
}

// readAWSCloudConfig reads an instance of AWSCloudConfig from config reader.
func readAWSCloudConfig(config io.Reader) (*AWSCloudConfig, error) {
	if config == nil {
		return nil, fmt.Errorf("no AWS cloud provider config file given")
	}

	var cfg AWSCloudConfig
	err := gcfg.ReadInto(&cfg, config)
	if err != nil {
		return nil, err
	}

	if cfg.Global.Region == "" {
		return nil, fmt.Errorf("no region specified in configuration file")
	}

	return &cfg, nil
}

// newAWSCloud creates a new instance of AWSCloud.
func newAWSCloud(config io.Reader, authFunc AuthFunc) (*AWSCloud, error) {
	cfg, err := readAWSCloudConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to read AWS cloud provider config file: %v", err)
	}

	auth, err := authFunc(cfg)
	if err != nil {
		return nil, err
	}

	region, ok := aws.Regions[cfg.Global.Region]
	if !ok {
		// Special-case for private clouds that support the EC2 API:
		//   if the region is actually a fqdn (has dots), then we use that as the endpoint
		// XXX: Should we extend the metadata services/ section instead?
		if strings.Contains(cfg.Global.Region, ".") {
			region.EC2Endpoint = "http://ec2." + cfg.Global.Region
		} else {
			return nil, fmt.Errorf("not a valid AWS region: %s", cfg.Global.Region)
		}
	}

	ec2 := ec2.New(auth, region)
	return &AWSCloud{
		ec2: ec2,
		cfg: cfg,
	}, nil
}

func (aws *AWSCloud) Clusters() (cloudprovider.Clusters, bool) {
	return nil, false
}

// TCPLoadBalancer returns an implementation of TCPLoadBalancer for Amazon Web Services.
func (aws *AWSCloud) TCPLoadBalancer() (cloudprovider.TCPLoadBalancer, bool) {
	return nil, false
}

// Instances returns an implementation of Instances for Amazon Web Services.
func (aws *AWSCloud) Instances() (cloudprovider.Instances, bool) {
	return aws, true
}

// Zones returns an implementation of Zones for Amazon Web Services.
func (aws *AWSCloud) Zones() (cloudprovider.Zones, bool) {
	return nil, false
}

// ExternalID returns the cloud provider ID of the specified instance.
func (aws *AWSCloud) ExternalID(name string) (string, error) {
	inst, err := aws.getInstancesByDnsName(name)
	if err != nil {
		return "", err
	}
	return inst.InstanceId, nil
}

// Return the instances matching the relevant private dns name.
func (aws *AWSCloud) getInstancesByDnsName(name string) (*ec2.Instance, error) {
	f := ec2.NewFilter()
	f.Add("private-dns-name", name)

	resp, err := aws.ec2.Instances(nil, f)
	if err != nil {
		return nil, err
	}

	instances := []*ec2.Instance{}
	for _, reservation := range resp.Reservations {
		for _, instance := range reservation.Instances {
			// TODO: Push down into filter?
			running := false
			switch instance.State.Name {
			case "shutting-down",
				"terminated", "stopping", "stopped":
				running = false
			case "pending", "running":
				running = true
			default:
				glog.Errorf("unknown EC2 instance state: %s", instance.State)
				running = false
			}

			if !running {
				continue
			}

			/*nameTag := ""
			for _, tag := range instance.Tags {
				if tag.Key == "Name" {
					nameTag = tag.Value
					break
				}
			}

			if nameTag != name {
				continue
			}*/
			if instance.PrivateDNSName != name {
				// TODO: Should we warn here? - the filter should have caught this
				// (this will happen in the tests if they don't fully mock the EC2 API)
				continue
			}

			instances = append(instances, &instance)
		}
	}

	if len(instances) == 0 {
		return nil, fmt.Errorf("no instances found for host: %s", name)
	}
	if len(instances) > 1 {
		return nil, fmt.Errorf("multiple instances found for host: %s", name)
	}
	return instances[0], nil
}

// GetNodeAddresses is an implementation of Instances.GetNodeAddresses.
func (aws *AWSCloud) GetNodeAddresses(name string) ([]api.NodeAddress, error) {
	instance, err := aws.getInstancesByDnsName(name)
	if err != nil {
		return nil, err
	}

	addresses := []api.NodeAddress{}

	// TODO: Other IP addresses (multiple ips)?
	if instance.PublicIpAddress != "" {
		ipAddress := instance.PublicIpAddress
		ip := net.ParseIP(ipAddress)
		if ip == nil {
			return nil, fmt.Errorf("EC2 instance had invalid public address: %s", instance.InstanceId)
		}
		address := api.NodeAddress{Kind: api.NodeExternalIPv4, Value: ip.String()}
		addresses = append(addresses, address)
	}

	if instance.PrivateIpAddress != "" {
		ipAddress := instance.PrivateIpAddress
		ip := net.ParseIP(ipAddress)
		if ip == nil {
			return nil, fmt.Errorf("EC2 instance had invalid private address: %s", instance.InstanceId)
		}
		address := api.NodeAddress{Kind: api.NodeInternalIPv4, Value: ip.String()}
		addresses = append(addresses, address)
	}

	return addresses, nil
}

// Return a list of instances matching regex string.
func (aws *AWSCloud) getInstancesByRegex(regex string) ([]string, error) {
	resp, err := aws.ec2.Instances(nil, nil)
	if err != nil {
		return []string{}, err
	}
	if resp == nil {
		return []string{}, fmt.Errorf("no InstanceResp returned")
	}

	if strings.HasPrefix(regex, "'") && strings.HasSuffix(regex, "'") {
		glog.Infof("Stripping quotes around regex (%s)", regex)
		regex = regex[1 : len(regex)-1]
	}

	re, err := regexp.Compile(regex)
	if err != nil {
		return []string{}, err
	}

	instances := []string{}
	for _, reservation := range resp.Reservations {
		for _, instance := range reservation.Instances {
			// TODO: Push down into filter?
			running := false
			switch instance.State.Name {
			case "shutting-down",
				"terminated", "stopping", "stopped":
				running = false
			case "pending", "running":
				running = true
			default:
				glog.Errorf("unknown EC2 instance state: %s", instance.State.Name)
				running = false
			}

			if !running {
				glog.Infof("skipping EC2 instance (not running): %s", instance.InstanceId)
				continue
			}

			nameTag := ""
			for _, tag := range instance.Tags {
				if tag.Key == "Name" {
					nameTag = tag.Value
					break
				}
			}

			if nameTag == "" || !re.MatchString(nameTag) {
				glog.Infof("skipping EC2 instance (name mismatch): %s (name=%s)", instance.InstanceId, nameTag)
				continue
			}

			glog.Infof("matched EC2 instance: %s (%s)", instance.InstanceId, instance.PrivateDNSName)
			// So name isn't really a unique identifier; we should do name = instance.PrivateDNSName
			// or (even better) name = instance.InstanceId
			// but we have to use name tag for the test e2e tests to pass..
			//name := nameTag
			name := instance.PrivateDNSName
			instances = append(instances, name)
		}
	}
	glog.Infof("Found instances: %s", instances)
	return instances, nil
}

// List is an implementation of Instances.List.
func (aws *AWSCloud) List(filter string) ([]string, error) {
	// TODO: Should really use tag query. No need to go regexp.
	return aws.getInstancesByRegex(filter)
}

func (aws *AWSCloud) GetNodeResources(name string) (*api.NodeResources, error) {
	return nil, nil
}
