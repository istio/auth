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
	"fmt"
	"io/ioutil"
	"time"

	"github.com/golang/glog"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"istio.io/auth/pkg/pki"
	"istio.io/auth/pkg/pki/ca"
	pb "istio.io/auth/proto"
)

const (
	// ONPREM Node Agent
	ONPREM int = iota // 0
	// GCP Node Agent
	GCP // 1
	// certRequestRetrialInterval is the retrial interval for certificate requests.
	certRequestRetrialInterval = time.Second * 5
	// certRequestMaxRetries is the number of retries for certificate requests.
	certRequestMaxRetries = 5
	// certRenewalGracePeriodPercentage indicates the length of the grace period in the
	// percentage of the entire certificate TTL.
	certRenewalGracePeriodPercentage = 50
)

// Config is Node agent configuration that is provided from CLI.
type Config struct {
	// Root CA cert file
	RootCACertFile string

	// Node Identity key file
	NodeIdentityPrivateKeyFile string

	// Node Identity certificate file
	NodeIdentityCertFile string

	// Service Identity
	ServiceIdentity string

	// Organization for service Identity
	ServiceIdentityOrg string

	// Directory where service identity private key and certificate
	// are written.
	ServiceIdentityDir string

	RSAKeySize int

	// Istio CA grpc server
	IstioCAAddress string

	// The environment this node agent is running on
	Env int
}

// This interface is provided for implementing platform specific code.
type platformSpecificRequest interface {
	GetDialOptions(*Config) ([]grpc.DialOption, error)
	// Whether the node agent is running on the right platform, e.g., if gcpPlatformImpl should only
	// run on GCE.
	IsProperPlatform() bool
}

// CAGrpcClient is for implementing the GRPC client to talk to CA.
type CAGrpcClient interface {
	// Send CSR to the CA and gets the response or error.
	SendCSR(*string, []grpc.DialOption, *pb.Request) (*pb.Response, error)
}

// CAGrpcClientImpl is a implementation of GRPC client to talk to CA.
type CAGrpcClientImpl struct {
}

// SendCSR sends CSR to CA through GRPC.
func (c *CAGrpcClientImpl) SendCSR(address *string, options []grpc.DialOption, req *pb.Request) (*pb.Response, error) {
	conn, err := grpc.Dial(*address, options...)
	if err != nil {
		glog.Errorf("Failed to dial %s: %s", *address, err)
		return nil, err
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			glog.Errorf("Failed to close connection")
		}
	}()
	client := pb.NewIstioCAServiceClient(conn)
	resp, err := client.HandleCSR(context.Background(), req)
	if err != nil {
		glog.Errorf("CSR request failed %v", err)
		return nil, err
	}
	return resp, nil
}

// The real node agent implementation. This implements the "Start" function
// in the NodeAgent interface.
type nodeAgentInternal struct {
	// Configuration specific to Node Agent
	config   *Config
	pr       platformSpecificRequest
	cAClient CAGrpcClient
}

// Start the node Agent with default setups.
func (na *nodeAgentInternal) Start() error {
	return na.StartWithArgs(certRequestRetrialInterval, certRequestMaxRetries, certRenewalGracePeriodPercentage)
}

// Start the node Agent with configs about retries.
func (na *nodeAgentInternal) StartWithArgs(interval time.Duration, maxRetries int, gracePeriodPercentage int) error {
	if na.config == nil {
		retErr := fmt.Errorf("node Agent configuration is nil")
		glog.Error(retErr)
		return retErr
	}

	if !na.pr.IsProperPlatform() {
		retErr := fmt.Errorf("node Agent is not running on the right platform")
		glog.Error(retErr)
		return retErr
	}

	glog.Infof("Node Agent starts successfully.")
	retries := 0
	retrialInterval := interval
	success := false
	for {
		privKey, req, reqErr := na.createRequest()
		if reqErr != nil {
			glog.Error(reqErr)
			return reqErr
		}

		dialOptions, optionErr := na.pr.GetDialOptions(na.config)
		if optionErr != nil {
			glog.Error(optionErr)
			return optionErr
		}

		glog.Infof("Sending CSR (retrial #%d) ...", retries)

		resp, err := na.cAClient.SendCSR(&na.config.IstioCAAddress, dialOptions, req)
		if err == nil && resp != nil && resp.IsApproved {
			waitTime, ttlErr := na.getWaitTimeFromCert(resp.SignedCertChain, time.Now(), gracePeriodPercentage)
			if ttlErr != nil {
				glog.Errorf("Error getting TTL from approved cert: %v", ttlErr)
				success = false
			} else {
				timer := time.NewTimer(waitTime)
				writeErr := na.writeToFile(privKey, resp.SignedCertChain)
				if writeErr != nil {
					retErr := fmt.Errorf("file write error: %v", writeErr)
					glog.Error(retErr)
					return retErr
				}
				glog.Infof("CSR is approved successfully. Will renew cert in %s", waitTime.String())
				retries = 0
				retrialInterval = certRequestRetrialInterval
				<-timer.C
				success = true
			}
		} else {
			success = false
		}

		if !success {
			if retries >= maxRetries {
				retErr := fmt.Errorf(
					"node agent can't get the CSR approved from Istio CA after max number of retries (%d)", maxRetries)
				glog.Error(retErr)
				return retErr
			}
			if err != nil {
				glog.Errorf("CSR signing failed: %v. Will retry in %s", err, retrialInterval.String())
			} else if resp == nil {
				glog.Errorf("CSR signing failed: response empty. Will retry in %s", retrialInterval.String())
			} else if !resp.IsApproved {
				glog.Errorf("CSR signing failed: request not approved. Will retry in %s", retrialInterval.String())
			} else {
				glog.Errorf("Certificate parsing error. Will retry in %s", retrialInterval.String())
			}
			timer := time.NewTimer(retrialInterval)
			retries++
			// Exponentially increase the backoff time.
			retrialInterval = retrialInterval * 2
			<-timer.C
		}
	}
}

func (na *nodeAgentInternal) createRequest() ([]byte, *pb.Request, error) {
	csr, privKey, err := ca.GenCSR(ca.CertOptions{
		Host:       na.config.ServiceIdentity,
		Org:        na.config.ServiceIdentityOrg,
		RSAKeySize: na.config.RSAKeySize,
	})

	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CSR: %v", err)
	}

	return privKey, &pb.Request{CsrPem: csr}, nil
}

func (na *nodeAgentInternal) getWaitTimeFromCert(
	certBytes []byte, now time.Time, gracePeriodPercentage int) (time.Duration, error) {
	cert, certErr := pki.ParsePemEncodedCertificate(certBytes)
	if certErr != nil {
		return time.Duration(0), certErr
	}
	timeToExpire := cert.NotAfter.Sub(now)
	if timeToExpire < 0 {
		return time.Duration(0), fmt.Errorf("certificate already expired at %s, but now is %s",
			cert.NotAfter, now)
	}
	gracePeriod := cert.NotAfter.Sub(cert.NotBefore) * time.Duration(gracePeriodPercentage) / time.Duration(100)
	// Wait until the grace period starts.
	waitTime := timeToExpire - gracePeriod
	if waitTime < 0 {
		waitTime = 0
	}
	return waitTime, nil
}

func (na *nodeAgentInternal) writeToFile(privKey []byte, cert []byte) error {
	glog.Infof("Write key and cert to local file.")
	if err := ioutil.WriteFile("serviceIdentityKey.pem", privKey, 0600); err != nil {
		return fmt.Errorf("cannot write service identity private key file")
	}
	if err := ioutil.WriteFile("serviceIdentityCert.pem", cert, 0644); err != nil {
		return fmt.Errorf("cannot write service identity certificate file")
	}
	return nil
}
