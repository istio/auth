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
// See the License for the specific language governing permissions and // limitations under the License.

package controller

import (
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
)

func TestAddService(t *testing.T) {
	test_cases := []struct {
		expectedValue map[string]sets.String
		initialValue  map[string]sets.String
		serviceToAdd  string
	}{
		{
			expectedValue: map[string]sets.String{
				"svc1": sets.NewString(),
				"svc2": sets.NewString("acct1"),
			},
			initialValue: map[string]sets.String{
				"svc2": sets.NewString("acct1"),
			},
			serviceToAdd: "svc1",
		},
		{
			expectedValue: map[string]sets.String{
				"svc1": sets.NewString("acct1"),
			},
			initialValue: map[string]sets.String{
				"svc1": sets.NewString("acct1"),
			},
			serviceToAdd: "svc1",
		},
	}

	for ind, test_case := range test_cases {
		m := NewSecureNamingMapping()
		m.mapping = test_case.initialValue
		m.AddService(test_case.serviceToAdd)

		if !reflect.DeepEqual(test_case.expectedValue, m.mapping) {
			t.Errorf("Case %d failed, actual mapping is %v but expected mapping is %v", ind, m.mapping, test_case.expectedValue)
		}
	}
}

func TestRemoveService(t *testing.T) {
	test_cases := []struct {
		expectedValue   map[string]sets.String
		initialValue    map[string]sets.String
		serviceToRemove string
	}{
		{
			expectedValue: map[string]sets.String{
				"svc1": sets.NewString(),
			},
			initialValue: map[string]sets.String{
				"svc1": sets.NewString(),
				"svc2": sets.NewString("acct1"),
			},
			serviceToRemove: "svc2",
		},
		{
			expectedValue: map[string]sets.String{
				"svc1": sets.NewString("acct1"),
			},
			initialValue: map[string]sets.String{
				"svc1": sets.NewString("acct1"),
			},
			serviceToRemove: "svc2",
		},
	}

	for ind, test_case := range test_cases {
		m := NewSecureNamingMapping()
		m.mapping = test_case.initialValue
		m.RemoveService(test_case.serviceToRemove)

		if !reflect.DeepEqual(test_case.expectedValue, m.mapping) {
			t.Errorf("Case %d failed, actual mapping is %v but expected mapping is %v", ind, m.mapping, test_case.expectedValue)
		}
	}
}

func TestSetServiceAccounts(t *testing.T) {
	test_cases := []struct {
		expectedValue map[string]sets.String
		initialValue  map[string]sets.String
		serviceName   string
		accounts      sets.String
	}{
		{
			expectedValue: map[string]sets.String{
				"svc1": sets.NewString("acct1", "acct2"),
			},
			initialValue: map[string]sets.String{
				"svc1": sets.NewString("acct3"),
			},
			serviceName: "svc1",
			accounts:    sets.NewString("acct1", "acct2"),
		},
		{
			expectedValue: map[string]sets.String{
				"svc1": sets.NewString("acct1", "acct2"),
				"svc2": sets.NewString("acct3"),
			},
			initialValue: map[string]sets.String{
				"svc2": sets.NewString("acct3"),
			},
			serviceName: "svc1",
			accounts:    sets.NewString("acct1", "acct2"),
		},
	}

	for ind, test_case := range test_cases {
		m := NewSecureNamingMapping()
		m.mapping = test_case.initialValue

		m.SetServiceAccounts(test_case.serviceName, test_case.accounts)

		if !reflect.DeepEqual(test_case.expectedValue, m.mapping) {
			t.Errorf("Case %d failed, actual mapping is %v but expected mapping is %v", ind, m.mapping, test_case.expectedValue)
		}
	}
}
