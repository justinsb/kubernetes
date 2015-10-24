#!/bin/bash

# Copyright 2014 The Kubernetes Authors All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Install rsync
# TODO: Move to image
apt-get update && apt-get install --yes rsync

# Fix problem with godep & aws-sdk-go (#16238)
# TODO: Fix properly
rm -rf /go/src/github.com/aws/aws-sdk-go/
go get github.com/aws/aws-sdk-go
pushd /go/src/github.com/aws/aws-sdk-go/
git checkout v0.9.9
popd


# Doesn't work with test output
export KUBE_COVER=n

export KUBE_TEST_API_VERSIONS=v1,extensions/v1beta1
export KUBE_TEST_ETCD_PREFIXES=registry
export KUBE_JUNIT_REPORT_DIR="/artifacts/testresults"
export CI_NAME="shippable"
export CI_BUILD_NUMBER="$BUILD_NUMBER"
export CI_BUILD_URL="$BUILD_URL"
export CI_BRANCH="$BRANCH"
export CI_PULL_REQUEST="$PULL_REQUEST"
# Set COVERALLS_REPO_TOKEN
#secure: hfh1Kwl2XYUlJCn4dtKSG0C9yXl5TtksVOY74OeqolvDAdVj4sc+GJD3Bywsp91CJe8YMEnkt9rN0WGI+gPVMcjTmZ9tMUxKiNNBP8m5oLRFbdgKOkNuXjpjpFHHWGAnNhMmh9vjI+ehADo+QIpU1fGxd3yO4tmIJ1qoK3QqvUrOZ1RwUubRXoeVn3xy3LK5yg4vP5ruitbNeWMw/RZZ7D6czvqvEfCgV6b4mdNDRMiqlUJNkaTRc3em1APXr30yagDV3a7hXLq3HdlyFwvF+9pmB4AKhQctyjPN4zvvPd0/gJXq3ZHXSlZXOZBMPXHlSS5pizfSInNszyZyrP3+/w==
./hack/install-etcd.sh
#export GOPATH=$SHIPPABLE_GOPATH
#mkdir -p ${GOPATH}/src/k8s.io; mv `pwd` ${GOPATH}/src/k8s.io/kubernetes
mkdir -p ${GOPATH}/src/k8s.io; ln -sf `pwd` ${GOPATH}/src/k8s.io/kubernetes
export PATH=$GOPATH/bin:./third_party/etcd:$PATH

cd ${GOPATH}/src/k8s.io/kubernetes

go get golang.org/x/tools/cmd/cover
go get github.com/mattn/goveralls
go get github.com/tools/godep
go get github.com/jstemmer/go-junit-report
./hack/build-go.sh
godep go install ./...
./hack/install-etcd.sh
./hack/verify-gofmt.sh
./hack/verify-boilerplate.sh
./hack/verify-description.sh
./hack/verify-flags-underscore.py
./hack/verify-godeps.sh ${BASE_BRANCH}
#./hack/travis/install-std-race.sh
./hack/verify-generated-conversions.sh
./hack/verify-generated-deep-copies.sh
./hack/verify-generated-docs.sh
./hack/verify-generated-swagger-docs.sh
./hack/verify-swagger-spec.sh
./hack/verify-linkcheck.sh

# Disable coverage collection on pull requests
KUBE_RACE="-race" KUBE_GOVERALLS_BIN="$GOPATH/bin/goveralls" KUBE_TIMEOUT='-timeout 300s' KUBE_COVERPROCS=8 KUBE_TEST_ETCD_PREFIXES="${KUBE_TEST_ETCD_PREFIXES}" KUBE_TEST_API_VERSIONS="${KUBE_TEST_API_VERSIONS}" ./hack/test-go.sh -- -p=2
./hack/test-cmd.sh
KUBE_TEST_API_VERSIONS="${KUBE_TEST_API_VERSIONS}" KUBE_INTEGRATION_TEST_MAX_CONCURRENCY=4 LOG_LEVEL=4 ./hack/test-integration.sh
./hack/test-update-storage-objects.sh

echo "SUCCESS"
