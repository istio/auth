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

package na

import (
	"fmt"

	"github.com/golang/glog"
	cred "istio.io/auth/pkg/credential"
)

// NodeAgent interface that should be implemented by
// various platform specific node agents.
type NodeAgent interface {
	Start() error
}

// NewNodeAgent is constructor for Node agent based on the provided Environment variable.
func NewNodeAgent(cfg *Config) NodeAgent {
	if cfg == nil {
		glog.Fatalf("Nil configuration passed")
	}
	na := &nodeAgentInternal{
		config: cfg,
	}

	switch cfg.Env {
	case "onprem":
		na.pr = &onPremPlatformImpl{cfg.CertChainFile}
	case "gcp":
		na.pr = &gcpPlatformImpl{&cred.GcpTokenFetcher{Aud: fmt.Sprintf("grpc://%s", cfg.IstioCAAddress)}}
	default:
		glog.Fatalf("Invalid env %s specified", cfg.Env)
	}

	client, err := NewCAGrpcClient(cfg, na.pr)
	if err != nil {
		glog.Fatalf("CA GRPC client creation failure: %v", err)
	}
	na.cAClient = client

	return na
}
