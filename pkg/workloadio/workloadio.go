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

package workloadio

import (
	"fmt"
	"istio.io/auth/pkg/workloadio/secretfile"
)

// WorkloadIO is for implementing the communication from the node agent to the workload.
type WorkloadIO interface {
	// SetServiceIdentityPrivateKey sets the service identity private key to the channel accessible to the workload.
	SetServiceIdentityPrivateKey([]byte) error
	// SetServiceIdentityCert sets the service identity cert to the channel accessible to the workload.
	SetServiceIdentityCert([]byte) error
}

func NewWorkloadIO(cfg Config) (WorkloadIO, error) {
	switch cfg.Mode {
	case SECRETFILE:
		return &secretfile.SecretFile{cfg.FileUtil, cfg.ServiceIdentityCertFile, cfg.ServiceIdentityPrivateKeyFile}, nil
	case WORKLOADAPI:
		return nil, fmt.Errorf("WORKLOAD API is unimplemented")
	default:
		return nil, fmt.Errorf("Mode is not supported: %d", cfg.Mode)
	}
}
