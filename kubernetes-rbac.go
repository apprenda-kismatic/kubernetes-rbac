// Copyright 2015 Kismatic Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package kubernetes-rbac contains the role-based access control (RBAC) plug-in for Kubernetes.
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/kismatic/kubernetes-rbac/authorization"
	"github.com/kismatic/kubernetes-rbac/repository/file"
	"github.com/kismatic/kubernetes-rbac/webhook"
	flag "github.com/spf13/pflag"
)

var flTLSCertFile = flag.String("tls-cert-file", "", "X509 certificate for HTTPS")
var flTLSKeyFile = flag.String("tls-private-key-file", "", "X509 private key matching --tls-cert-file for HTTPS")
var flPolicyFile = flag.String("rbac-policy-file", "rbac-policy.json", "File that defines the RBAC policy")
var flDebug = flag.Bool("debug", false, "enable debug logging")

func main() {
	flag.Parse()

	if !*flDebug {
		log.SetOutput(ioutil.Discard)
	}

	if *flTLSCertFile == "" {
		fmt.Fprintln(os.Stderr, "--tls-cert-file is required.")
		os.Exit(1)
	}

	if *flTLSKeyFile == "" {
		fmt.Fprintln(os.Stderr, "--tls-private-key-file is required.")
		os.Exit(1)
	}

	repo, err := file.Create(*flPolicyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating repo: %v", err)
	}

	rg := authorization.RepoRuleGetter{repo}
	h := &webhook.AuthorizationHandler{&rg}

	http.Handle("/authorize", h)

	log.Fatal(http.ListenAndServeTLS(":4000", *flTLSCertFile, *flTLSKeyFile, nil))

}
