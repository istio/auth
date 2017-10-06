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

package secretfile

import (
	"istio.io/auth/pkg/util"
)

const (
	KeyFilePermission  = 0600
	CertFilePermission = 0644
)

type SecretFile struct {
	// FileUtil supports the writing operations to the FS.
	FileUtil util.FileUtil

	// ServiceIdentityCertFile specifies the file containing generated service identity certificate.
	ServiceIdentityCertFile string

	// ServiceIdentityPrivateKeyFile specifies the file containing generated service identity private key.
	ServiceIdentityPrivateKeyFile string
}

func (sf *SecretFile) SetServiceIdentityPrivateKey(content []byte) error {
	return sf.FileUtil.Write(sf.ServiceIdentityPrivateKeyFile, content, KeyFilePermission)
}

func (sf *SecretFile) SetServiceIdentityCert(content []byte) error {
	return sf.FileUtil.Write(sf.ServiceIdentityCertFile, content, CertFilePermission)
}
