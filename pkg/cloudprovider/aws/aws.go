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
	"sync"

	"code.google.com/p/gcfg"
	"github.com/mitchellh/goamz/aws"
	"github.com/mitchellh/goamz/ec2"
	"github.com/mitchellh/goamz/elb"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/api/resource"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/cloudprovider"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/util"

	"github.com/golang/glog"
)

const LOADBALANCER_NAME_PREFIX = "k8s-"
const LOADBALANCER_TAG_NAME = "k8s:name"
const LOADBALANCER_NAME_MAXLEN = 32 // AWS limits load balancer names to 32 characters

// TODO: Should we rename this to AWS (EBS & ELB are not technically part of EC2)
// Abstraction over EC2, to allow mocking/other implementations
type EC2 interface {
	// Query EC2 for instances matching the filter
	Instances(instIds []string, filter *ec2InstanceFilter) (resp *ec2.InstancesResp, err error)

	// Query the EC2 metadata service (used to discover instance-id etc)
	GetMetaData(key string) ([]byte, error)

	// TODO: It is weird that these take a region.  I suspect it won't work cross-region anwyay.
	// TODO: Refactor to use a load balancer object?
	// List load balancers
	DescribeLoadBalancers(region string, name string) (map[string]elb.LoadBalancer, error)
	// Create load balancer
	CreateLoadBalancer(region string, request *elb.CreateLoadBalancer) (string, error)
	// Add backends to load balancer
	RegisterInstancesWithLoadBalancer(region string, request *elb.RegisterInstancesWithLoadBalancer) ([]elb.Instance, error)
	// Remove backends from load balancer
	DeregisterInstancesFromLoadBalancer(region string, request *elb.DeregisterInstancesFromLoadBalancer) ([]elb.Instance, error)
	// Delete load balancer
	DeleteLoadBalancer(region string, name string) error

	// List subnets
	DescribeSubnets(subnetIds []string, filterVpcId string) ([]ec2.Subnet, error)

	// List security groups
	DescribeSecurityGroups(groupIds []string, filterName string, filterVpcId string) ([]ec2.SecurityGroupInfo, error)
	// Create security group and return the id
	CreateSecurityGroup(vpcId string, name string, description string) (string, error)
	// Authorize security group ingress
	AuthorizeSecurityGroupIngress(securityGroupId string, perms []ec2.IPPerm) (resp *ec2.SimpleResp, err error)

	// List VPCs
	ListVpcs(filterName string) ([]ec2.VPC, error)
}

// AWSCloud is an implementation of Interface, TCPLoadBalancer and Instances for Amazon Web Services.
type AWSCloud struct {
	ec2              EC2
	cfg              *AWSCloudConfig
	availabilityZone string
	region           aws.Region
}

type AWSCloudConfig struct {
	Global struct {
		// TODO: Is there any use for this?  We can get it from the instance metadata service
		Region string
	}
}

// Similar to ec2.Filter, but the filter values can be read from tests
// (ec2.Filter only has private members)
type ec2InstanceFilter struct {
	PrivateDNSName string
}

// True if the passed instance matches the filter
func (f *ec2InstanceFilter) Matches(instance ec2.Instance) bool {
	if f.PrivateDNSName != "" && instance.PrivateDNSName != f.PrivateDNSName {
		return false
	}
	return true
}

// goamzEC2 is an implementation of the EC2 interface, backed by goamz
type goamzEC2 struct {
	auth aws.Auth
	ec2  *ec2.EC2

	mutex      sync.Mutex
	elbClients map[string]*elb.ELB
}

func newGoamzEC2(auth aws.Auth, regionName string) (*goamzEC2, error) {
	region, ok := aws.Regions[regionName]
	if !ok {
		return nil, fmt.Errorf("not a valid AWS region: %s", regionName)
	}

	self := &goamzEC2{}
	self.ec2 = ec2.New(auth, region)
	self.auth = auth
	self.elbClients = make(map[string]*elb.ELB)
	return self, nil
}

// Find the kubernetes vpc
func (self *goamzEC2) ListVpcs(filterName string) ([]ec2.VPC, error) {
	client := self.ec2

	// TODO: How do we want to identify our VPC?
	filter := ec2.NewFilter()
	filter.Add("tag:Name", filterName)

	ids := []string{}
	response, err := client.DescribeVpcs(ids, filter)
	if err != nil {
		glog.Error("error listing VPCs", err)
		return nil, err
	}

	vpcs := response.VPCs
	return vpcs, nil
}

// Builds an ELB client for the specified region
func (self *goamzEC2) getElbClient(regionName string) (*elb.ELB, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	region, ok := aws.Regions[regionName]
	if !ok {
		return nil, fmt.Errorf("not a valid AWS region: %s", regionName)
	}
	elbClient, found := self.elbClients[region.Name]
	if !found {
		elbClient = elb.New(self.auth, region)
		self.elbClients[region.Name] = elbClient
	}
	return elbClient, nil
}

// Implementation of EC2.Instances
func (self *goamzEC2) Instances(instanceIds []string, filter *ec2InstanceFilter) (resp *ec2.InstancesResp, err error) {
	var goamzFilter *ec2.Filter
	if filter != nil {
		goamzFilter = ec2.NewFilter()
		if filter.PrivateDNSName != "" {
			goamzFilter.Add("private-dns-name", filter.PrivateDNSName)
		}
	}
	return self.ec2.Instances(instanceIds, goamzFilter)
}

func (self *goamzEC2) GetMetaData(key string) ([]byte, error) {
	v, err := aws.GetMetaData(key)
	if err != nil {
		return nil, fmt.Errorf("Error querying AWS metadata for key %s: %v", key, err)
	}
	return v, nil
}

// Implements EC2.DescribeLoadBalancers
func (self *goamzEC2) DescribeLoadBalancers(region string, findName string) (map[string]elb.LoadBalancer, error) {
	client, err := self.getElbClient(region)
	if err != nil {
		return nil, err
	}

	request := &elb.DescribeLoadBalancer{}
	// Names are limited to 32 characters, so we must use tags
	//request.Names = []string{findName}
	response, err := client.DescribeLoadBalancers(request)
	if err != nil {
		elbError, ok := err.(*elb.Error)
		if ok && elbError.Code == "LoadBalancerNotFound" {
			// Not found
			return nil, nil
		}
		glog.Error("error describing load balancers: ", err)
		return nil, err
	}

	loadBalancersByAwsId := map[string]elb.LoadBalancer{}
	for _, loadBalancer := range response.LoadBalancers {
		awsId := loadBalancer.LoadBalancerName
		if !strings.HasPrefix(awsId, LOADBALANCER_NAME_PREFIX) {
			continue
		}

		// TODO: Cache the name -> tag mapping (it should never change)
		loadBalancersByAwsId[awsId] = loadBalancer
	}

	loadBalancersByName := map[string]elb.LoadBalancer{}
	if len(loadBalancersByAwsId) != 0 {
		describeTagsRequest := &elb.DescribeTags{}
		describeTagsRequest.LoadBalancerNames = []string{}
		for awsId := range loadBalancersByAwsId {
			describeTagsRequest.LoadBalancerNames = append(describeTagsRequest.LoadBalancerNames, awsId)
		}
		describeTagsResponse, err := client.DescribeTags(describeTagsRequest)
		if err != nil {
			glog.Error("error describing tags for load balancers: ", err)
			return nil, err
		}

		if describeTagsResponse.NextToken != "" {
			// TODO: Implement this
			err := fmt.Errorf("error describing tags for load balancers - pagination not implemented")
			return nil, err
		}

		for _, loadBalancerTag := range describeTagsResponse.LoadBalancerTags {
			awsId := loadBalancerTag.LoadBalancerName
			name := ""
			for _, tag := range loadBalancerTag.Tags {
				if tag.Key == LOADBALANCER_TAG_NAME {
					name = tag.Value
				}
			}
			if name == "" {
				glog.Warning("Ignoring load balancer with no k8s name tag: ", awsId)
				continue
			}

			if findName != "" && name != findName {
				continue
			}

			loadBalancer, ok := loadBalancersByAwsId[awsId]
			if !ok {
				// This might almost be panic-worthy!
				glog.Error("unexpected internal error - did not find load balancer")
				continue
			}
			loadBalancersByName[name] = loadBalancer
		}
	}
	return loadBalancersByName, nil
}

// Implements EC2.CreateLoadBalancer
func (self *goamzEC2) CreateLoadBalancer(region string, request *elb.CreateLoadBalancer) (string, error) {
	client, err := self.getElbClient(region)
	if err != nil {
		return "", err
	}

	response, err := client.CreateLoadBalancer(request)
	if err != nil {
		glog.Error("error creating load balancer: ", err)
		return "", err
	}
	return response.DNSName, nil
}

// Implements EC2.DeleteLoadBalancer
func (self *goamzEC2) DeleteLoadBalancer(region string, name string) error {
	client, err := self.getElbClient(region)
	if err != nil {
		return err
	}

	request := &elb.DeleteLoadBalancer{}
	request.LoadBalancerName = name

	_, err = client.DeleteLoadBalancer(request)
	if err != nil {
		glog.Error("error deleting load balancer: ", err)
		return err
	}
	return nil
}

// Implements EC2.RegisterInstancesWithLoadBalancer
func (self *goamzEC2) RegisterInstancesWithLoadBalancer(region string, request *elb.RegisterInstancesWithLoadBalancer) ([]elb.Instance, error) {
	client, err := self.getElbClient(region)
	if err != nil {
		return nil, err
	}

	response, err := client.RegisterInstancesWithLoadBalancer(request)
	if err != nil {
		glog.Error("error registering instances with load balancer: ", err)
		return nil, err
	}
	return response.Instances, nil
}

// Implements EC2.DeregisterInstancesFromLoadBalancer
func (self *goamzEC2) DeregisterInstancesFromLoadBalancer(region string, request *elb.DeregisterInstancesFromLoadBalancer) ([]elb.Instance, error) {
	client, err := self.getElbClient(region)
	if err != nil {
		return nil, err
	}

	response, err := client.DeregisterInstancesFromLoadBalancer(request)
	if err != nil {
		glog.Error("error deregistering instances from load balancer: ", err)
		return nil, err
	}
	return response.Instances, nil
}

// Implements EC2.DescribeSubnets
func (self *goamzEC2) DescribeSubnets(subnetIds []string, filterVpcId string) ([]ec2.Subnet, error) {
	filter := ec2.NewFilter()
	if filterVpcId != "" {
		filter.Add("vpc-id", filterVpcId)
	}
	response, err := self.ec2.DescribeSubnets(subnetIds, filter)
	if err != nil {
		glog.Error("error describing subnets: ", err)
		return nil, err
	}
	return response.Subnets, nil
}

// Implements EC2.DescribeSecurityGroups
func (self *goamzEC2) DescribeSecurityGroups(securityGroupIds []string, filterName string, filterVpcId string) ([]ec2.SecurityGroupInfo, error) {
	filter := ec2.NewFilter()
	if filterName != "" {
		filter.Add("group-name", filterName)
	}
	if filterVpcId != "" {
		filter.Add("vpc-id", filterVpcId)
	}
	var findGroups []ec2.SecurityGroup
	if securityGroupIds != nil {
		findGroups = []ec2.SecurityGroup{}
		for _, securityGroupId := range securityGroupIds {
			findGroup := ec2.SecurityGroup{Id: securityGroupId}
			findGroups = append(findGroups, findGroup)
		}
	}

	response, err := self.ec2.SecurityGroups(findGroups, filter)
	if err != nil {
		glog.Error("error describing groups: ", err)
		return nil, err
	}
	return response.Groups, nil
}

// Implements EC2.CreateSecurityGroup
func (self *goamzEC2) CreateSecurityGroup(vpcId string, name string, description string) (string, error) {
	request := ec2.SecurityGroup{}
	request.VpcId = vpcId
	request.Name = name
	request.Description = description
	response, err := self.ec2.CreateSecurityGroup(request)
	if err != nil {
		glog.Error("error creating security group: ", err)
		return "", err
	}

	return response.Id, nil
}

// Implements EC2.AuthorizeSecurityGroupIngess
func (self *goamzEC2) AuthorizeSecurityGroupIngress(securityGroupId string, perms []ec2.IPPerm) (resp *ec2.SimpleResp, err error) {
	groupSpec := ec2.SecurityGroup{Id: securityGroupId}

	response, err := self.ec2.AuthorizeSecurityGroup(groupSpec, perms)
	if err != nil {
		glog.Error("error creating security group: ", err)
		return nil, err
	}

	return response, nil
}

type AuthFunc func() (auth aws.Auth, err error)

func init() {
	cloudprovider.RegisterCloudProvider("aws", func(config io.Reader) (cloudprovider.Interface, error) {
		return newAWSCloud(config, getAuth)
	})
}

func getAuth() (auth aws.Auth, err error) {
	return aws.GetAuth("", "")
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

	auth, err := authFunc()
	if err != nil {
		return nil, err
	}

	// TODO: We can get the region very easily from the instance-metadata service
	region, ok := aws.Regions[cfg.Global.Region]
	if !ok {
		return nil, fmt.Errorf("not a valid AWS region: %s", cfg.Global.Region)
	}

	ec2, err := newGoamzEC2(auth, cfg.Global.Region)
	if err != nil {
		return nil, err
	}

	return &AWSCloud{
		ec2:    ec2,
		cfg:    cfg,
		region: region,
	}, nil
}

func (self *AWSCloud) getAvailabilityZone() (string, error) {
	// TODO: Do we need sync.Mutex here?
	availabilityZone := self.availabilityZone
	if self.availabilityZone == "" {
		availabilityZoneBytes, err := self.ec2.GetMetaData("placement/availability-zone")
		if err != nil {
			return "", err
		}
		if availabilityZoneBytes == nil || len(availabilityZoneBytes) == 0 {
			return "", fmt.Errorf("Unable to determine availability-zone from instance metadata")
		}
		availabilityZone = string(availabilityZoneBytes)
		self.availabilityZone = availabilityZone
	}
	return availabilityZone, nil
}

func (aws *AWSCloud) Clusters() (cloudprovider.Clusters, bool) {
	return nil, false
}

// TCPLoadBalancer returns an implementation of TCPLoadBalancer for Amazon Web Services.
func (self *AWSCloud) TCPLoadBalancer() (cloudprovider.TCPLoadBalancer, bool) {
	return self, true
}

// Instances returns an implementation of Instances for Amazon Web Services.
func (aws *AWSCloud) Instances() (cloudprovider.Instances, bool) {
	return aws, true
}

// Zones returns an implementation of Zones for Amazon Web Services.
func (aws *AWSCloud) Zones() (cloudprovider.Zones, bool) {
	return aws, true
}

// NodeAddresses is an implementation of Instances.NodeAddresses.
func (aws *AWSCloud) NodeAddresses(name string) ([]api.NodeAddress, error) {
	inst, err := aws.getInstanceByDnsName(name)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(inst.PrivateIpAddress)
	if ip == nil {
		return nil, fmt.Errorf("invalid network IP: %s", inst.PrivateIpAddress)
	}

	return []api.NodeAddress{{Type: api.NodeLegacyHostIP, Address: ip.String()}}, nil
}

// ExternalID returns the cloud provider ID of the specified instance.
func (aws *AWSCloud) ExternalID(name string) (string, error) {
	inst, err := aws.getInstanceByDnsName(name)
	if err != nil {
		return "", err
	}
	return inst.InstanceId, nil
}

// Return the instances matching the relevant private dns name.
func (aws *AWSCloud) getInstanceByDnsName(name string) (*ec2.Instance, error) {
	f := &ec2InstanceFilter{}
	f.PrivateDNSName = name

	resp, err := aws.ec2.Instances(nil, f)
	if err != nil {
		return nil, err
	}

	instances := []*ec2.Instance{}
	for _, reservation := range resp.Reservations {
		for _, instance := range reservation.Instances {
			// TODO: Push running logic down into filter?
			if !isAlive(&instance) {
				continue
			}

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

// Check if the instance is alive (running or pending)
// We typically ignore instances that are not alive
func isAlive(instance *ec2.Instance) bool {
	switch instance.State.Name {
	case "shutting-down", "terminated", "stopping", "stopped":
		return false
	case "pending", "running":
		return true
	default:
		glog.Errorf("unknown EC2 instance state: %s", instance.State)
		return false
	}
}

// TODO: Make efficient
func (self *AWSCloud) getInstancesByDnsNames(names []string) ([]*ec2.Instance, error) {
	instances := []*ec2.Instance{}
	for _, name := range names {
		instance, err := self.getInstanceByDnsName(name)
		if err != nil {
			return nil, err
		}
		if instance == nil {
			return nil, fmt.Errorf("unable to find instance " + name)
		}
		instances = append(instances, instance)
	}
	return instances, nil
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
			// TODO: Push filtering down into EC2 API filter?
			if !isAlive(&instance) {
				glog.V(2).Infof("skipping EC2 instance (not alive): %s", instance.InstanceId)
				continue
			}

			for _, tag := range instance.Tags {
				if tag.Key == "Name" && re.MatchString(tag.Value) {
					instances = append(instances, instance.PrivateDNSName)
					break
				}
			}
		}
	}
	glog.V(2).Infof("Matched EC2 instances: %s", instances)
	return instances, nil
}

// List is an implementation of Instances.List.
func (aws *AWSCloud) List(filter string) ([]string, error) {
	// TODO: Should really use tag query. No need to go regexp.
	return aws.getInstancesByRegex(filter)
}

// GetNodeResources implements Instances.GetNodeResources
func (aws *AWSCloud) GetNodeResources(name string) (*api.NodeResources, error) {
	instance, err := aws.getInstanceByDnsName(name)
	if err != nil {
		return nil, err
	}

	resources, err := getResourcesByInstanceType(instance.InstanceType)
	if err != nil {
		return nil, err
	}

	return resources, nil
}

// Builds an api.NodeResources
// cpu is in ecus, memory is in GiB
// We pass the family in so that we could provide more info (e.g. GPU or not)
func makeNodeResources(family string, cpu float64, memory float64) (*api.NodeResources, error) {
	return &api.NodeResources{
		Capacity: api.ResourceList{
			api.ResourceCPU:    *resource.NewMilliQuantity(int64(cpu*1000), resource.DecimalSI),
			api.ResourceMemory: *resource.NewQuantity(int64(memory*1024*1024*1024), resource.BinarySI),
		},
	}, nil
}

// Maps an EC2 instance type to k8s resource information
func getResourcesByInstanceType(instanceType string) (*api.NodeResources, error) {
	// There is no API for this (that I know of)
	switch instanceType {
	// t2: Burstable
	// TODO: The ECUs are fake values (because they are burstable), so this is just a guess...
	case "t1.micro":
		return makeNodeResources("t1", 0.125, 0.615)

		// t2: Burstable
		// TODO: The ECUs are fake values (because they are burstable), so this is just a guess...
	case "t2.micro":
		return makeNodeResources("t2", 0.25, 1)
	case "t2.small":
		return makeNodeResources("t2", 0.5, 2)
	case "t2.medium":
		return makeNodeResources("t2", 1, 4)

		// c1: Compute optimized
	case "c1.medium":
		return makeNodeResources("c1", 5, 1.7)
	case "c1.xlarge":
		return makeNodeResources("c1", 20, 7)

		// cc2: Compute optimized
	case "cc2.8xlarge":
		return makeNodeResources("cc2", 88, 60.5)

		// cg1: GPU instances
	case "cg1.4xlarge":
		return makeNodeResources("cg1", 33.5, 22.5)

		// cr1: Memory optimized
	case "cr1.8xlarge":
		return makeNodeResources("cr1", 88, 244)

		// c3: Compute optimized
	case "c3.large":
		return makeNodeResources("c3", 7, 3.75)
	case "c3.xlarge":
		return makeNodeResources("c3", 14, 7.5)
	case "c3.2xlarge":
		return makeNodeResources("c3", 28, 15)
	case "c3.4xlarge":
		return makeNodeResources("c3", 55, 30)
	case "c3.8xlarge":
		return makeNodeResources("c3", 108, 60)

		// c4: Compute optimized
	case "c4.large":
		return makeNodeResources("c4", 8, 3.75)
	case "c4.xlarge":
		return makeNodeResources("c4", 16, 7.5)
	case "c4.2xlarge":
		return makeNodeResources("c4", 31, 15)
	case "c4.4xlarge":
		return makeNodeResources("c4", 62, 30)
	case "c4.8xlarge":
		return makeNodeResources("c4", 132, 60)

		// g2: GPU instances
	case "g2.2xlarge":
		return makeNodeResources("g2", 26, 15)

		// hi1: Storage optimized (SSD)
	case "hi1.4xlarge":
		return makeNodeResources("hs1", 35, 60.5)

		// hs1: Storage optimized (HDD)
	case "hs1.8xlarge":
		return makeNodeResources("hs1", 35, 117)

		// m1: General purpose
	case "m1.small":
		return makeNodeResources("m1", 1, 1.7)
	case "m1.medium":
		return makeNodeResources("m1", 2, 3.75)
	case "m1.large":
		return makeNodeResources("m1", 4, 7.5)
	case "m1.xlarge":
		return makeNodeResources("m1", 8, 15)

		// m2: Memory optimized
	case "m2.xlarge":
		return makeNodeResources("m2", 6.5, 17.1)
	case "m2.2xlarge":
		return makeNodeResources("m2", 13, 34.2)
	case "m2.4xlarge":
		return makeNodeResources("m2", 26, 68.4)

		// m3: General purpose
	case "m3.medium":
		return makeNodeResources("m3", 3, 3.75)
	case "m3.large":
		return makeNodeResources("m3", 6.5, 7.5)
	case "m3.xlarge":
		return makeNodeResources("m3", 13, 15)
	case "m3.2xlarge":
		return makeNodeResources("m3", 26, 30)

		// i2: Storage optimized (SSD)
	case "i2.xlarge":
		return makeNodeResources("i2", 14, 30.5)
	case "i2.2xlarge":
		return makeNodeResources("i2", 27, 61)
	case "i2.4xlarge":
		return makeNodeResources("i2", 53, 122)
	case "i2.8xlarge":
		return makeNodeResources("i2", 104, 244)

		// r3: Memory optimized
	case "r3.large":
		return makeNodeResources("r3", 6.5, 15)
	case "r3.xlarge":
		return makeNodeResources("r3", 13, 30.5)
	case "r3.2xlarge":
		return makeNodeResources("r3", 26, 61)
	case "r3.4xlarge":
		return makeNodeResources("r3", 52, 122)
	case "r3.8xlarge":
		return makeNodeResources("r3", 104, 244)

	default:
		glog.Errorf("unknown instanceType: %s", instanceType)
		return nil, nil
	}
}

// GetZone implements Zones.GetZone
func (self *AWSCloud) GetZone() (cloudprovider.Zone, error) {
	availabilityZone, err := self.getAvailabilityZone()
	if err != nil {
		return cloudprovider.Zone{}, err
	}
	return cloudprovider.Zone{
		FailureDomain: availabilityZone,
		Region:        self.region.Name,
	}, nil
}

// Gets the current load balancer state
func (self *AWSCloud) describeLoadBalancer(region, name string) (*elb.LoadBalancer, error) {
	loadBalancers, err := self.ec2.DescribeLoadBalancers(region, name)
	if err != nil {
		return nil, err
	}

	var ret *elb.LoadBalancer
	for _, loadBalancer := range loadBalancers {
		if ret != nil {
			glog.Errorf("Found multiple load balancers with name: %s", name)
		}
		ret = &loadBalancer
	}
	return ret, nil
}

// TCPLoadBalancerExists implements TCPLoadBalancer.TCPLoadBalancerExists.
func (self *AWSCloud) TCPLoadBalancerExists(name, region string) (bool, error) {
	lb, err := self.describeLoadBalancer(name, region)
	if err != nil {
		return false, err
	}

	if lb != nil {
		return true, nil
	}
	return false, nil
}

// Find the kubernetes vpc
func (self *AWSCloud) findVpc() (*ec2.VPC, error) {
	name := "kubernetes-vpc"
	vpcs, err := self.ec2.ListVpcs(name)
	if err != nil {
		return nil, err
	}
	if len(vpcs) == 0 {
		return nil, nil
	}
	if len(vpcs) == 1 {
		return &vpcs[0], nil
	}
	return nil, fmt.Errorf("Found multiple matching VPCs for name: %s", name)
}

func mapToInstanceIds(instances []*ec2.Instance) []string {
	ids := make([]string, 0, len(instances))
	for _, instance := range instances {
		ids = append(ids, instance.InstanceId)
	}
	return ids
}

func (self *AWSCloud) ensureSecurityGroupIngess(securityGroupId string, sourceIp string, protocol string, fromPort, toPort int) (bool, error) {
	groups, err := self.ec2.DescribeSecurityGroups([]string{securityGroupId}, "", "")
	if err != nil {
		glog.Warning("error retrieving security group", err)
		return false, err
	}

	if len(groups) == 0 {
		return false, fmt.Errorf("security group not found")
	}

	if len(groups) != 1 {
		return false, fmt.Errorf("multiple security groups found with same id")
	}

	group := groups[0]

	for _, permission := range group.IPPerms {
		if permission.FromPort != fromPort {
			continue
		}
		if permission.ToPort != toPort {
			continue
		}
		if permission.Protocol != protocol {
			continue
		}
		if len(permission.SourceIPs) != 1 {
			continue
		}
		if permission.SourceIPs[0] != sourceIp {
			continue
		}
		return false, nil
	}

	newPermission := ec2.IPPerm{}
	newPermission.FromPort = fromPort
	newPermission.ToPort = toPort
	newPermission.SourceIPs = []string{sourceIp}
	newPermission.Protocol = protocol

	newPermissions := []ec2.IPPerm{newPermission}
	_, err = self.ec2.AuthorizeSecurityGroupIngress(securityGroupId, newPermissions)
	if err != nil {
		glog.Warning("error authorizing security group ingress", err)
		return false, err
	}

	return true, nil
}

// CreateTCPLoadBalancer implements TCPLoadBalancer.CreateTCPLoadBalancer
func (self *AWSCloud) CreateTCPLoadBalancer(name, region string, externalIP net.IP, port int, hosts []string, affinity api.AffinityType) (string, error) {
	glog.V(2).Infof("CreateTCPLoadBalancer(%v, %v, %v, %v, %v)", name, region, externalIP, port, hosts)

	if affinity != api.AffinityTypeNone {
		// ELB supports sticky sessions, but only when configured for HTTP/HTTPS
		return "", fmt.Errorf("unsupported load balancer affinity: %v", affinity)
	}

	if len(externalIP) > 0 {
		return "", fmt.Errorf("External IP cannot be specified for AWS ELB")
	}

	instances, err := self.getInstancesByDnsNames(hosts)
	if err != nil {
		return "", err
	}

	vpc, err := self.findVpc()
	if err != nil {
		glog.Error("error finding vpc", err)
		return "", err
	}
	if vpc == nil {
		return "", fmt.Errorf("Unable to find vpc")
	}

	// Construct list of configured subnets
	subnetIds := []string{}
	{
		subnets, err := self.ec2.DescribeSubnets(nil, vpc.VpcId)
		if err != nil {
			return "", err
		}

		//	zones := []string{}
		for _, subnet := range subnets {
			subnetIds = append(subnetIds, subnet.SubnetId)
			if !strings.HasPrefix(subnet.AvailabilityZone, region) {
				glog.Error("found AZ that did not match region", subnet.AvailabilityZone, " vs ", region)
				return "", fmt.Errorf("invalid AZ for region")
			}
			//		zones = append(zones, subnet.AvailabilityZone)
		}
	}

	// Build the load balancer itself
	var loadBalancerName, dnsName string
	{
		loadBalancer, err := self.describeLoadBalancer(region, name)
		if err != nil {
			return "", err
		}

		if loadBalancer == nil {
			createRequest := &elb.CreateLoadBalancer{}
			// TODO: Is there a k8s UUID that it would make sense to use?
			uuid := strings.Replace(string(util.NewUUID()), "-", "", -1)
			awsId := LOADBALANCER_NAME_PREFIX + uuid
			if len(awsId) > LOADBALANCER_NAME_MAXLEN {
				awsId = awsId[:LOADBALANCER_NAME_MAXLEN]
			}
			createRequest.LoadBalancerName = awsId

			listener := elb.Listener{}
			listener.InstancePort = int64(port)
			listener.LoadBalancerPort = int64(port)
			listener.Protocol = "tcp"
			listener.InstanceProtocol = "tcp"
			createRequest.Listeners = []elb.Listener{listener}

			// TODO: Should we use a better identifier (the kubernetes uuid?)
			//	nameTag := &elb.Tag{ Key: "Name", Value: name}
			//	createRequest.Tags = []Tag { nameTag }

			//	zones := []string{"us-east-1a"}
			//	createRequest.AvailZone = removeDuplicates(zones)

			// We are supposed to specify one subnet per AZ.
			// TODO: What happens if we have more than one subnet per AZ?
			createRequest.Subnets = subnetIds

			sgName := "k8s-elb-" + name
			sgDescription := "Security group for Kubernetes ELB " + name

			{
				// TODO: Should we do something more reliable ?? .Where("tag:kubernetes-id", kubernetesId)
				securityGroups, err := self.ec2.DescribeSecurityGroups(nil, sgName, vpc.VpcId)
				if err != nil {
					return "", err
				}
				var securityGroupId string
				for _, securityGroup := range securityGroups {
					securityGroupId = securityGroup.Id
				}
				if securityGroupId == "" {
					securityGroupId, err = self.ec2.CreateSecurityGroup(vpc.VpcId, sgName, sgDescription)
					if err != nil {
						return "", err
					}
				}
				_, err = self.ensureSecurityGroupIngess(securityGroupId, "0.0.0.0/0", "tcp", port, port)
				if err != nil {
					return "", err
				}
				createRequest.SecurityGroups = []string{securityGroupId}
			}

			if len(externalIP) > 0 {
				return "", fmt.Errorf("External IP cannot be specified for AWS ELB")
			}

			glog.Info("Creating load balancer with name: ", createRequest.LoadBalancerName)
			createdDnsName, err := self.ec2.CreateLoadBalancer(region, createRequest)
			if err != nil {
				return "", err
			}
			dnsName = createdDnsName
			loadBalancerName = createRequest.LoadBalancerName
		} else {
			// TODO: Verify that load balancer configuration matches?
			dnsName = loadBalancer.DNSName
			loadBalancerName = loadBalancer.LoadBalancerName
		}
	}

	registerRequest := &elb.RegisterInstancesWithLoadBalancer{}
	registerRequest.LoadBalancerName = loadBalancerName
	registerRequest.Instances = mapToInstanceIds(instances)

	attachedInstances, err := self.ec2.RegisterInstancesWithLoadBalancer(region, registerRequest)
	if err != nil {
		return "", err
	}

	glog.V(1).Info("Updated instances registered with load-balancer", name, attachedInstances)
	glog.V(1).Info("Loadbalancer %s has DNS name %s", name, dnsName)

	// TODO: Wait for creation?

	return dnsName, nil
}

// DeleteTCPLoadBalancer implements TCPLoadBalancer.DeleteTCPLoadBalancer.
func (self *AWSCloud) DeleteTCPLoadBalancer(name, region string) error {
	// TODO: Delete security group

	lb, err := self.describeLoadBalancer(region, name)
	if err != nil {
		return err
	}

	if lb == nil {
		glog.Info("Load balancer already deleted: ", name)
		return nil
	}

	err = self.ec2.DeleteLoadBalancer(region, lb.LoadBalancerName)
	if err != nil {
		return err
	}
	return nil
}

// UpdateTCPLoadBalancer implements TCPLoadBalancer.UpdateTCPLoadBalancer
func (self *AWSCloud) UpdateTCPLoadBalancer(name, region string, hosts []string) error {
	instances, err := self.getInstancesByDnsNames(hosts)
	if err != nil {
		return err
	}

	lb, err := self.describeLoadBalancer(region, name)
	if err != nil {
		return err
	}

	if lb == nil {
		return fmt.Errorf("Load balancer not found")
	}

	existingInstances := map[string]*elb.Instance{}
	for _, instance := range lb.Instances {
		existingInstances[instance.InstanceId] = &instance
	}

	wantInstances := map[string]*ec2.Instance{}
	for _, instance := range instances {
		wantInstances[instance.InstanceId] = instance
	}

	addInstances := []string{}
	for key := range wantInstances {
		_, found := existingInstances[key]
		if !found {
			addInstances = append(addInstances, key)
		}
	}

	removeInstances := []string{}
	for key := range existingInstances {
		_, found := wantInstances[key]
		if !found {
			removeInstances = append(removeInstances, key)
		}
	}

	if len(addInstances) > 0 {
		registerRequest := &elb.RegisterInstancesWithLoadBalancer{}
		registerRequest.Instances = addInstances
		registerRequest.LoadBalancerName = lb.LoadBalancerName
		_, err = self.ec2.RegisterInstancesWithLoadBalancer(region, registerRequest)
		if err != nil {
			return err
		}
	}

	if len(removeInstances) > 0 {
		deregisterRequest := &elb.DeregisterInstancesFromLoadBalancer{}
		deregisterRequest.Instances = removeInstances
		deregisterRequest.LoadBalancerName = lb.LoadBalancerName
		_, err = self.ec2.DeregisterInstancesFromLoadBalancer(region, deregisterRequest)
		if err != nil {
			return err
		}
	}

	return nil
}
