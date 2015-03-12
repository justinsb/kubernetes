## Getting started on AWS

### Prerequisites

1. You need an AWS account. Visit [http://aws.amazon.com](http://aws.amazon.com) to get started
2. Install and configure [AWS Command Line Interface](http://aws.amazon.com/cli)
3. You need an AWS [instance profile and role](http://docs.aws.amazon.com/IAM/latest/UserGuide/instance-profiles.html) with EC2 full access.

### Cluster turnup

#### Download Kubernetes
##### a) Preferred Option: Install from [0.10.0 release](https://github.com/GoogleCloudPlatform/kubernetes/releases/tag/v0.10.0)
1. ```wget https://github.com/GoogleCloudPlatform/kubernetes/releases/download/v0.10.0/kubernetes.tar.gz```
2. ```tar -xzf kubernetes.tar.gz; cd kubernetes```
3. ```export PATH=$PATH:$PWD/platforms/<os>/<platform>```

##### b) Alternate Option: Install from source at head
1. ```git clone https://github.com/GoogleCloudPlatform/kubernetes.git```
2. ```cd kubernetes; make release```
3. ```export PATH=$PATH:$PWD/_output/local/bin/<os>/<platform>```

#### Create IAM instance profiles

# TODO: Move to script?
# TODO: Reduce permissions

This profile will initially have no permissions, but you can add any needed permissions to it later.
```
cat > kubernetes-master-role.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
aws iam create-role --role-name kubernetes-master --assume-role-policy-document file://kubernetes-master-role.json

cat > kubernetes-master-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ec2:*"],
      "Resource": ["*"]
    },
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::kubernetes-*"
      ]
    }
  ]
}
EOF
aws iam put-role-policy --role-name kubernetes-master --policy-name kubernetes-master --policy-document file://kubernetes-master-policy.json

aws iam create-instance-profile --instance-profile-name kubernetes-master
aws iam add-role-to-instance-profile --instance-profile-name kubernetes-master --role-name kubernetes-master


cat > kubernetes-minion-role.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
aws iam create-role --role-name kubernetes-minion --assume-role-policy-document file://kubernetes-minion-role.json

cat > kubernetes-minion-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::kubernetes-*"
      ]
    }
  ]
}
EOF
aws iam put-role-policy --role-name kubernetes-minion --policy-name kubernetes-minion --policy-document file://kubernetes-minion-policy.json

aws iam create-instance-profile --instance-profile-name kubernetes-minion
aws iam add-role-to-instance-profile --instance-profile-name kubernetes-minion --role-name kubernetes-minion
```

#### Turn up the cluster
```
export KUBERNETES_PROVIDER=aws
cluster/kube-up.sh
```

The script above relies on AWS S3 to deploy the software to instances running in EC2.

NOTE: The script will provision a new VPC and a 5 node k8s cluster in us-west-2 (Oregon). It'll also try to create or
reuse a keypair called "kubernetes", and IAM profiles called "kubernetes-master" and "kubernetes-minion".  If these
already exist, make sure you want them to be used here.

Once the cluster is up, it will print the ip address of your cluster, this process takes about 5 to 10 minutes.

```
export KUBERNETES_MASTER=https://<ip-address>
```

Also setup your path to point to the released binaries:
```
export PATH=$PATH:$PWD:/cluster
```

### Running examples

Take a look at [next steps](https://github.com/GoogleCloudPlatform/kubernetes#where-to-go-next)

### Tearing down the cluster
```
cd kubernetes
cluster/kube-down.sh
```

### Cloud Formation [optional]
There is a contributed [example](aws-coreos.md) from [CoreOS](http://www.coreos.com) using Cloud Formation.
