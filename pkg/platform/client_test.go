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
	"reflect"
	"testing"

	cred "istio.io/auth/pkg/credential"
)

func TestNewClientConfig(t *testing.T) {
	testCases := map[string]struct {
		platform    string
		cfg         ClientConfig
		expectedErr string
	}{
		"onprem env": {
			platform: "onprem",
			cfg:      &OnPremClientConfig{},
		},
		"gcp env": {
			platform: "gcp",
			cfg:      &GcpClientConfig{},
		},
		"aws env": {
			platform: "aws",
			cfg:      &AwsClientConfig{},
		},
		"unknown env": {
			platform:    "babel",
			expectedErr: "Invalid env babel specified",
		},
	}

	for id, c := range testCases {
		cc, err := NewClientConfig(c.platform)
		if len(c.expectedErr) == 0 {
			if err == nil {
				if !reflect.DeepEqual(cc, c.cfg) {
					t.Errorf("%s: Wrong config returned. Expected %v, Actual %v", id, c.cfg, cc)
				}
			} else {
				t.Errorf("%s: Unexpected err: %v", id, err)
			}
		} else {
			if err == nil {
				t.Errorf("%s: Succeeded. Error expected: %s", id, c.expectedErr)
			} else {
				if err.Error() != c.expectedErr {
					t.Errorf("%s: Incorrect error message. Expected %s, Actual %s", id, c.expectedErr, err.Error())
				}
			}
		}
	}
}

func TestNewClient(t *testing.T) {
	testCases := map[string]struct {
		platform       string
		cfg            ClientConfig
		caAddr         string
		expectedErr    string
		expectedClient Client
	}{
		"onprem env": {
			platform:       "onprem",
			cfg:            &OnPremClientConfig{},
			expectedClient: &OnPremClientImpl{&OnPremClientConfig{}},
		},
		"gcp env": {
			platform: "gcp",
			cfg:      &GcpClientConfig{},
			expectedClient: &GcpClientImpl{
				cfg:     &GcpClientConfig{},
				fetcher: &cred.GcpTokenFetcher{Aud: fmt.Sprintf("grpc://%s", "fake-ca:9999")},
			},
			caAddr: "fake-ca:9999",
		},
		"aws env": {
			platform: "aws",
			cfg:      &AwsClientConfig{},
			expectedClient: &AwsClientImpl{
				cfg: &AwsClientConfig{},
			},
		},
		"unknown env": {
			platform:    "babel",
			expectedErr: "Invalid env babel specified",
		},
	}

	for id, c := range testCases {
		pc, err := NewClient(c.platform, c.cfg, c.caAddr)

		if _, ok := pc.(*AwsClientImpl); ok {
			pc := pc.(*AwsClientImpl)
			pc.client = nil
		}

		if len(c.expectedErr) == 0 {
			if err == nil {
				if !reflect.DeepEqual(pc, c.expectedClient) {
					t.Errorf("%s: Wrong client returned. Expected %s, Actual %s", id, c.expectedClient, pc)
				}
			} else {
				t.Errorf("%s: Unexpected err: %v", id, err)
			}
		} else {
			if err == nil {
				t.Errorf("%s: Succeeded. Error expected: %s", id, c.expectedErr)
			} else {
				if err.Error() != c.expectedErr {
					t.Errorf("%s: Incorrect error message. Expected %s, Actual %s", id, c.expectedErr, err.Error())
				}
			}
		}
	}
}
