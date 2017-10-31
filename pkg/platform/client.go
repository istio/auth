// Copyright 2017 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package platform

import (
	"fmt"

	flag "github.com/spf13/pflag"
	"google.golang.org/grpc"
)

// ClientConfig is the interface for platform configs
type ClientConfig interface {
	GetFlagSet() *flag.FlagSet
}

// Client is the interface for implementing the client to access platform metadata.
type Client interface {
	GetDialOptions() ([]grpc.DialOption, error)
	// Whether the node agent is running on the right platform, e.g., if gcpPlatformImpl should only
	// run on GCE.
	IsProperPlatform() bool
	// Get the service identity.
	GetServiceIdentity() (string, error)
	// Get node agent credential
	GetAgentCredential() ([]byte, error)
	// Get type of the credential
	GetCredentialType() string
}

// NewClientConfig returns the platform config object
func NewClientConfig(platform string) (ClientConfig, error) {
	switch platform {
	case "onprem":
		return &OnPremClientConfig{}, nil
	case "gcp":
		return &GcpClientConfig{}, nil
	case "aws":
		return &AwsClientConfig{}, nil
	default:
		return nil, fmt.Errorf("Invalid env %s specified", platform)
	}
}

// NewClient is the function to create implementations of the platform metadata client.
func NewClient(platform string, cfg ClientConfig, caAddr string) (Client, error) {
	switch platform {
	case "onprem":
		return NewOnPremClientImpl(cfg), nil
	case "gcp":
		return NewGcpClientImpl(cfg, caAddr), nil
	case "aws":
		return NewAwsClientImpl(cfg), nil
	default:
		return nil, fmt.Errorf("Invalid env %s specified", platform)
	}
}
