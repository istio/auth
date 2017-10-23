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
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// AwsClientImpl is the implementation of AWS metadata client.
type AwsClientImpl struct {
	client *ec2metadata.EC2Metadata
}

// GetDialOptions returns the GRPC dial options to connect to the CA.
func (pi *AwsClientImpl) GetDialOptions(cfg *ClientConfig) ([]grpc.DialOption, error) {
	creds, err := credentials.NewClientTLSFromFile(cfg.RootCACertFile, "")
	if err != nil {
		return nil, err
	}

	options := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	return options, nil
}

// IsProperPlatform returns whether the AWS platform client is available.
func (pi *AwsClientImpl) IsProperPlatform() bool {
	return pi.client.Available()
}

// GetServiceIdentity extracts service identity from userdata. This function should be
// pluggable for different AWS deployments in the future.
func (pi *AwsClientImpl) GetServiceIdentity() (string, error) {
	return "", nil
}

// GetAgentCredential retrieves the instance identity document as the
// agent credential used by node agent
func (pi *AwsClientImpl) GetAgentCredential() ([]byte, error) {
	doc, err := pi.client.GetInstanceIdentityDocument()
	if err != nil {
		return []byte{}, fmt.Errorf("Failed to get EC2 instance identity document: %v", err)
	}

	bytes, err := json.Marshal(doc)
	if err != nil {
		return []byte{}, fmt.Errorf("Failed to marshal identity document %v: %v", doc, err)
	}

	return bytes, nil
}

// GetCredentialType returns the credential type as "aws".
func (pi *AwsClientImpl) GetCredentialType() string {
	return "aws"
}
