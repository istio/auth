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

package main

import (
	"io/ioutil"
	"os"

	"github.com/golang/glog"
	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"

	"istio.io/auth/cmd/node_agent/na"
	"istio.io/auth/pkg/cmd"
	"istio.io/auth/pkg/platform"
)

var (
	naConfig na.Config

	rootCmd = &cobra.Command{
		Run: func(cmd *cobra.Command, args []string) {
			runNodeAgent(cmd.Flags())
		},
	}
)

func init() {
	na.InitializeConfig(&naConfig)

	flags := rootCmd.Flags()
	flags.SetOutput(ioutil.Discard) // suppress warnings output during flag parsing

	flags.StringVar(&naConfig.ServiceIdentityOrg, "org", "", "Organization for the cert")
	flags.IntVar(&naConfig.RSAKeySize, "key-size", 1024, "Size of generated private key")
	flags.StringVar(&naConfig.IstioCAAddress,
		"ca-address", "istio-ca:8060", "Istio CA address")
	flags.StringVar(&naConfig.Env, "env", "onprem", "Node Environment : onprem | gcp | aws | ...")
	flags.StringVar(&naConfig.ServiceCertFile, "service-cert", "/etc/cert.pem", "Service account certificate location")
	flags.StringVar(&naConfig.ServiceKeyFile, "service-priv-key", "/etc/key.pem", "Service account private key location")

	cmd.InitializeFlags(rootCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		glog.Error(err)
		os.Exit(-1)
	}
}

func runNodeAgent(flags *flag.FlagSet) {
	cc, err := platform.NewClientConfig(naConfig.Env)
	if err != nil {
		glog.Error(err)
		os.Exit(-1)
	}

	// parse custom flags
	cFlags := cc.GetFlagSet()
	cFlags.AddFlagSet(flags)
	err = cFlags.Parse(os.Args[1:])
	if err != nil {
		glog.Error(err)
		os.Exit(-1)
	}

	naConfig.PlatformConfig = cc
	nodeAgent, err := na.NewNodeAgent(&naConfig)
	if err != nil {
		glog.Error(err)
		os.Exit(-1)
	}

	glog.Infof("Starting Node Agent")
	if err := nodeAgent.Start(); err != nil {
		glog.Errorf("Node agent terminated with error: %v.", err)
		os.Exit(-1)
	}
}
