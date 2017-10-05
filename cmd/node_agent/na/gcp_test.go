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
	"errors"
	"reflect"
	"testing"

	"google.golang.org/grpc"
)

const (
	token = "abcdef"
)

// mockTokenFetcher implements the mock token fetcher.
type mockTokenFetcher struct {
	token        string
	errorMessage string
}

// A mock fetcher for FetchToken.
func (fetcher *mockTokenFetcher) FetchToken() (string, error) {
	var err error

	if len(fetcher.errorMessage) > 0 {
		err = errors.New(fetcher.errorMessage)
	}

	return token, err
}

func TestGetDialOptions(t *testing.T) {
	testCases := map[string]struct {
		config         *Config
		optionsLen     int
		token          string
		tokenFetchErr  string
		expectedErr    string
		expectedOption uintptr
	}{
		"nil configuration": {
			config: &Config{
				RootCACertFile: "testdata/cert-chain-good.pem",
			},
			optionsLen:    0,
			token:         "abcdef",
			expectedErr:   "Nil configuration passed",
			tokenFetchErr: "Nil configuration passed",
		},
		"Token fetch error": {
			config: &Config{
				RootCACertFile: "testdata/cert-chain-good.pem",
			},
			optionsLen:    0,
			token:         "",
			expectedErr:   "Nil configuration passed",
			tokenFetchErr: "Nil configuration passed",
		},
		"Root certificate file read error": {
			config: &Config{
				RootCACertFile: "testdata/cert-chain-good_not_exist.pem",
			},
			optionsLen:    0,
			token:         token,
			tokenFetchErr: "",
			expectedErr:   "open testdata/cert-chain-good_not_exist.pem: no such file or directory",
		},
		"Token fetched": {
			config: &Config{
				RootCACertFile: "testdata/cert-chain-good.pem",
			},
			optionsLen:     2,
			token:          token,
			tokenFetchErr:  "",
			expectedOption: reflect.ValueOf(grpc.WithPerRPCCredentials(&jwtAccess{token})).Pointer(),
		},
	}

	for id, c := range testCases {
		gcp := gcpPlatformImpl{&mockTokenFetcher{c.token, c.tokenFetchErr}}

		options, err := gcp.GetDialOptions(c.config)
		if len(c.expectedErr) > 0 {
			if err == nil {
				t.Errorf("Succeeded. Error expected: %v", err)
			} else if err.Error() != c.expectedErr {
				t.Errorf("%s: incorrect error message: %s VS %s",
					id, err.Error(), c.expectedErr)
			}
		} else if err != nil {
			t.Fatalf("Unexpected Error: %v", err)
		}

		// Make sure there're two dial options, one for TLS and one for JWT.
		if len(options) != c.optionsLen {
			t.Errorf("Wrong dial options size. Exptcted %v, Actual %v", c.optionsLen, len(options))
		}

		if len(options) > 0 {
			expectedOption := grpc.WithPerRPCCredentials(&jwtAccess{token})
			if reflect.ValueOf(options[0]).Pointer() != reflect.ValueOf(expectedOption).Pointer() {
				t.Errorf("Wrong option found")
			}
		}
	}
}
