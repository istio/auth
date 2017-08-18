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
	"io/ioutil"
	"time"

	"github.com/golang/glog"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"istio.io/auth/pkg/pki/ca"
	pb "istio.io/auth/proto"
)

const (
	// ONPREM Node Agent
	ONPREM int = iota // 0
	// GCP Node Agent
	GCP // 1
)

// Config is Node agent configuration that is provided from CLI.
type Config struct {
	// Root CA cert file
	RootCACertFile *string

	// Node Identity key file
	NodeIdentityPrivateKeyFile *string

	// Node Identity certificate file
	NodeIdentityCertFile *string

	// Service Identity
	ServiceIdentity *string

	// Service Identity
	ServiceIdentityOrg *string

	// Directory where service identity private key and certificate
	// are written.
	ServiceIdentityDir *string

	RSAKeySize *int

	// cert renewal cutoff
	PercentageExpirationTime *int

	// Istio CA grpc server
	IstioCAAddress *string

	// The environment this node agent is running on
	Env *int
}

// This interface is provided for implementing platform specific code.
type platformSpecificRequest interface {
	GetDialOptions(*Config) ([]grpc.DialOption, error)
	// Whether the node agent is running on the right platform, e.g., if gcpPlatformImpl should only
	// run on GCE.
	IsProperPlatform() bool
}

// The real node agent implementation. This implements the "Start" function
// in the NodeAgent interface.
type nodeAgentInternal struct {
	// Configuration specific to Node Agent
	config *Config
	pr     platformSpecificRequest
}

// Start the node Agent.
func (na *nodeAgentInternal) Start() {

	if na.config == nil {
		glog.Fatalf("Node Agent configuration is nil")
	}

	if !na.pr.IsProperPlatform() {
		glog.Fatalf("Node Agent is not running on the right platform")
	}

	glog.Info("Node Agent starts successfully.")
	for {
		privKey, resp, err := na.sendCSR()
		if err != nil {
			glog.Errorf("CSR signing failed: %s", err)
		} else if resp != nil && resp.IsApproved {
			timer := time.NewTimer(na.getExpTime(resp))
			glog.Info("CSR is approved successfully.")
			na.writeToFile(privKey, resp.SignedCertChain)
			<-timer.C
		}
	}
}

func (na *nodeAgentInternal) createRequest() ([]byte, *pb.Request) {
	csr, privKey, err := ca.GenCSR(ca.CertOptions{
		Host:       *na.config.ServiceIdentity,
		Org:        *na.config.ServiceIdentityOrg,
		RSAKeySize: *na.config.RSAKeySize,
	})

	if err != nil {
		glog.Fatalf("Failed to generate CSR: %s", err)
	}

	return privKey, &pb.Request{
		CsrPem: csr,
	}
}

func (na *nodeAgentInternal) sendCSR() ([]byte, *pb.Response, error) {
	glog.Info("Sending out CSR to CA...")
	dialOptions, err := na.pr.GetDialOptions(na.config)
	if err != nil {
		glog.Errorf("Cannot construct the dial options with error %s", err)
		return nil, nil, err
	}
	conn, err := grpc.Dial(*na.config.IstioCAAddress, dialOptions...)
	if err != nil {
		glog.Fatalf("Failed ot dial %s: %s", *na.config.IstioCAAddress, err)
	}

	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			glog.Fatalf("Failed ot close connection")
		}
	}()

	client := pb.NewIstioCAServiceClient(conn)
	privKey, req := na.createRequest()
	resp, err := client.HandleCSR(context.Background(), req)
	if err != nil {
		glog.Errorf("CSR request failed %s", err)
		return nil, nil, err
	}

	return privKey, resp, nil
}

func (na *nodeAgentInternal) writeToFile(privKey []byte, cert []byte) {
	glog.Info("Write key and cert to local file.")
	if err := ioutil.WriteFile("serviceIdentityKey.pem", privKey, 0600); err != nil {
		glog.Fatalf("Cannot write service identity private key file")
	}
	if err := ioutil.WriteFile("serviceIdentityCert.pem", cert, 0644); err != nil {
		glog.Fatalf("Cannot write service identity certificate file")
	}
}

func (na *nodeAgentInternal) getExpTime(resp *pb.Response) time.Duration {
	// TODO: extract expiration time from certificate contained in the response object.
	return 0
}
