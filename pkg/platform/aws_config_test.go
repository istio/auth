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
	"testing"
)

func TestAWSConfigDefaultValue(t *testing.T) {
	c := &AwsClientConfig{}

	flags := c.GetFlagSet()
	_ = flags.Parse([]string{})

	if c.RootCACertFile != flags.Lookup("root-cert").DefValue {
		t.Errorf("AWS Default Config Flag: wrong default value. Expected %s, Actual %s",
			flags.Lookup("root-cert").DefValue, c.RootCACertFile)
	}
}

func TestAWSFlag(t *testing.T) {
	c := &AwsClientConfig{}

	flags := c.GetFlagSet()
	certLoc := "/etc/root.cert.pem"
	_ = flags.Parse([]string{"--root-cert", certLoc})

	if c.RootCACertFile != certLoc {
		t.Errorf("AWS Config Flag: wrong value. Expected %s, Actual %s", certLoc, c.RootCACertFile)
	}
}
