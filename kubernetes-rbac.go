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
	"log"
	"net/http"
	"os"

	"github.com/kismatic/kubernetes-rbac/webhook"
	flag "github.com/spf13/pflag"
)

var flTLSCertFile = flag.String("tls-cert-file", "", "X509 certificate for HTTPS")
var flTLSKeyFile = flag.String("tls-private-key-file", "", "X509 private key matching --tls-cert-file for HTTPS")

func main() {
	flag.Parse()

	h := &webhook.AuthorizationHandler{}

	http.Handle("/authorize", h)

	if *flTLSCertFile == "" {
		fmt.Fprintln(os.Stderr, "--tls-cert-file is required.")
		os.Exit(1)
	}

	if *flTLSKeyFile == "" {
		fmt.Fprintln(os.Stderr, "--tls-private-key-file is required.")
		os.Exit(1)
	}

	log.Fatal(http.ListenAndServeTLS(":4000", *flTLSCertFile, *flTLSKeyFile, nil))

}
