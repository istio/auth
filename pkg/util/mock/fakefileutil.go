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

package mock

import (
	"fmt"
	"os"
)

// FileImpl is an implementation of File.
type FakeFileUtil struct {
	ReadContent  map[string][]byte
	WriteContent map[string][]byte
}

// Read reads the file named by filename and returns all the contents until EOF or an error.
func (f FakeFileUtil) Read(filename string) ([]byte, error) {
	if f.ReadContent[filename] != nil {
		return f.ReadContent[filename], nil
	}
	return nil, fmt.Errorf("File not found.")
}

// Write writes data to a file named by filename.
func (f FakeFileUtil) Write(filename string, content []byte, perm os.FileMode) error {
	if f.WriteContent == nil {
		f.WriteContent = make(map[string][]byte)
	}
	fmt.Printf("Oliver %s:%s", filename, content)
	f.WriteContent[filename] = content
	return nil
}
