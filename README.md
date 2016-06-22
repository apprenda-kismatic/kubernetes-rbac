# kubernetes-rbac
[![Build Status](https://travis-ci.org/kismatic/kubernetes-rbac.svg?branch=master)](https://travis-ci.org/kismatic/kubernetes-rbac)
[![Go Report Card](https://goreportcard.com/badge/github.com/kismatic/kubernetes-rbac)](https://goreportcard.com/report/github.com/kismatic/kubernetes-rbac)
[![GoDoc](https://godoc.org/github.com/kismatic/kubernetes-rbac?status.svg)](https://godoc.org/github.com/kismatic/kubernetes-rbac)
[![Slack Status](http://slack.k6c.io/badge.svg)](http://slack.k6c.io)

Kubernetes role-based access control (RBAC) plug-in

## Project Status

Kubernetes RBAC is at an early stage and under active development. We do not recommend its use in production, but we encourage you to try out Kubernetes RBAC and provide feedback via issues and pull requests.

## Getting Started
The project provides RBAC for Kubernetes via an authorization webhook.

Pre-requisites
--------------
* Certificate / private key pair for the webhook service
* Certificate / private key pair for the Kubernetes webhook client

Defining RBAC policy
--------------------
The role-based access control plugin allows cluster operators to define RBAC policy. As of now, the policy is defined in a JSON file with two main constructs:
* Role: Named role in a given namespace that contains a collection of policy rules 
* Cluster Role: Similar to a Role, expect it is a cluster-wide role
* Role Binding: Binds a role or a cluster role to a collection of subjects in a specific namespace
* Cluster Role Binding: Binds a cluster role to a collection of subjects

See sample-policy.json for more details.

Starting the Webhook service
----------------------------
```
kubernetes-rbac --tls-cert-file pathToCertFile --tls-private-key-file patoToPrivateKey --rbac-policy-file pathToRbacPolicyJsonFile 
```

Configuring the Authorization webhook
-------------------------------------
Create a yaml file to define the webhook:
```
# clusters refers to the remote service.
clusters:
  - name: authz-webhook
    cluster:
      certificate-authority: /someCert.cert        # CA for verifying the remote service.
      server: https://authz-webhook:4000/authorize # URL of remote service to query. Must use 'https'.

# users refers to the K8s API Server's webhook configuration.
users:
  - name: authz-webhook-client
    user:
      client-certificate: /webhook-client.cert # cert for the webhook plugin to use
      client-key: /webhook-client.key          # key matching the cert

# kubeconfig files require a context. Provide one for the API Server.
current-context: authz-webhook
contexts:
- context:
    cluster: authz-webhook
    user: authz-webhook-client
  name: authz-webhook
```

Set the following flags when starting the K8s API Server:
```
--authorization-mode=Webhook # Specify Webhook authorization mode
--authorization-webhook-config-file=/root/authz-webhook.yaml # path to the webhook yaml
--authorization-webhook-cache-authorized-ttl=30m0s # set authorized response cache TTL
--authorization-webhook-cache-unauthorized-ttl=5m0s # set unauthorized response cache TTL
```

## Contributing to Kubernetes RBAC

Kubernetes RBAC is an open source project and contributors are welcome!
Join us on IRC at [#kismatic on freenode.net](http://webchat.freenode.net/?channels=%23kismatic&uio=d4), [file an issue](https://github.com/kismatic/kubernetes-rbac/issues) here on Github.

## Licensing

Unless otherwise noted, all code in the Kubernetes RBAC repository is licensed under the [Apache 2.0 license](LICENSE). Some portions of the codebase are derived from other projects under different licenses; the appropriate information can be found in the header of those source files, as applicable.
