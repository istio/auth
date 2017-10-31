#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR=$(echo $DIR | sed 's:/*$::')

# Load libraries
. ${DIR}/bash-utilities || { echo "Cannot load Bash utilities" ; exit 1 ; }

# End to End tests options
SECURITY_KEY_OUTPUT_DIR=`pwd`/docker
DOCKER_IMAGE="istio-ca-test,node-agent-test"
ARGS="--image $DOCKER_IMAGE"
HUB=""
TAG=""
K8S_NAMESPACE="istio-ca-integration-"$(cat /dev/urandom | tr -dc 'a-z' | fold -w 8 | head -n 1)
ISTIO_CA_PORT=8060
EXTERNAL_IP_ADDRESS=""

set -ex

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      TAG=$2
      shift
      ;;
    --hub)
      HUB=$2
      shift
      ;;
    *)
      ARGS="$ARGS $1"
  esac

  shift
done

if [[ -z $TAG ]]; then
  TAG=$(whoami)_$(date +%Y%m%d_%H%M%S)
fi
ARGS="$ARGS --tag $TAG"

if [[ -z $HUB ]]; then
  HUB="gcr.io/istio-testing"
fi
ARGS="$ARGS --hub $HUB"

if [[ "$HUB" =~ ^gcr\.io ]]; then
  gcloud docker --authorize-only
fi

# Generate certificate and private key from root
echo 'Generate certificate and private key from root'
retry -n 3 run bazel run $BAZEL_ARGS //cmd/generate_cert -- \
-out-cert=${SECURITY_KEY_OUTPUT_DIR}/istio_ca.crt \
-out-priv=${SECURITY_KEY_OUTPUT_DIR}/istio_ca.key \
-organization="k8s.cluster.local" \
-self-signed=true \
-ca=true

# Generate certificate and private key from istio_ca
retry -n 3 run bazel run $BAZEL_ARGS //cmd/generate_cert -- \
-out-cert=${SECURITY_KEY_OUTPUT_DIR}/node_agent.crt \
-out-priv=${SECURITY_KEY_OUTPUT_DIR}/node_agent.key \
-organization="NodeAgent" \
-host="nodeagent.google.com" \
-signer-cert=${SECURITY_KEY_OUTPUT_DIR}/istio_ca.crt \
-signer-priv=${SECURITY_KEY_OUTPUT_DIR}/istio_ca.key

# Build and push the Istio-CA and NodeAgent docker images
retry -n 3 run bin/push-docker.sh -i "$DOCKER_IMAGE" -h $HUB -t $TAG

# Prepare environments
echo 'Creating a new namespace'
retry -n 10 kubectl create namespace $K8S_NAMESPACE

echo 'Creating a role'
retry -n 3 kubectl create -n $K8S_NAMESPACE -f test/role.yaml

echo 'Creating a role-binding'
retry -n 3 kubectl create -n $K8S_NAMESPACE -f test/role-binding.yaml

# istio-ca instance
echo 'Create istio-ca instance'
retry -n 3 kubectl run istio-ca \
--image=$HUB/istio-ca-test:$TAG \
--port=$ISTIO_CA_PORT \
-n $K8S_NAMESPACE

echo 'Create the istio-ca service'
retry -n 3 kubectl expose deployment istio-ca \
--type=LoadBalancer \
-n $K8S_NAMESPACE

echo 'Check internal IP address of the service is ready'
retry -n 10 check_service_internal_ip_ready istio-ca $K8S_NAMESPACE

# Test istio.default secret creation
echo 'Check istio.default secret was created'
retry -n 5 check_secret "istio.default" $K8S_NAMESPACE

echo 'Remove istio.default secret'
run ${KUBECTL} delete secrets "istio.default" -n "${K8S_NAMESPACE}"

echo 'Check istio.default secret was created again'
retry -n 5 check_secret "istio.default" $K8S_NAMESPACE

# NodeAgent instance
echo 'Create a new node-agent instance'
retry -n 3 kubectl run node-agent \
--image=$HUB/node-agent-test:$TAG \
--port=$ISTIO_CA_PORT \
-n $K8S_NAMESPACE

# Check key files on NodeAgent are updated and valid
echo 'Check key files of Node Agent were updated'
retry -n 5 wait_certificate_update_and_verify \
"${SECURITY_KEY_OUTPUT_DIR}/node_agent.crt" \
"${SECURITY_KEY_OUTPUT_DIR}/node_agent.key" \
"${SECURITY_KEY_OUTPUT_DIR}/istio_ca.crt" $K8S_NAMESPACE

echo 'Cleaning up objects'
retry -n 3 kubectl delete namespace $K8S_NAMESPACE
