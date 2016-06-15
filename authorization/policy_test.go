package authorization

import (
	"testing"

	"github.com/kismatic/kubernetes-rbac/api"
)

type dummyRuleGetter struct {
	rules []api.PolicyRule
}

func (drg dummyRuleGetter) GetApplicableRules(user string, groups []string, namespace string) []api.PolicyRule {
	return drg.rules
}

func TestIsAuthorized(t *testing.T) {

	req := &Request{
		Action: APIAction{
			Verb:      "GET",
			Resource:  "pods",
			Name:      "nginx",
			Namespace: "project-1",
		},
	}

	rulesThatAuthorize := []api.PolicyRule{
		{
			// Allow all access
			Verbs:     []string{"*"},
			APIGroups: []string{"*"},
			Resources: []string{"*"},
		},
		{
			// Allow all GET requests
			Verbs:     []string{"GET"},
			APIGroups: []string{"*"},
			Resources: []string{"*"},
		},
		{
			// Allow all requests on the pods resource
			Verbs:     []string{"*"},
			APIGroups: []string{"*"},
			Resources: []string{"pods"},
		},
		{
			// Allow GET requests on the pods resource
			Verbs:     []string{"GET"},
			APIGroups: []string{"*"},
			Resources: []string{"pods"},
		},
	}

	for i, r := range rulesThatAuthorize {
		drg := dummyRuleGetter{[]api.PolicyRule{r}}

		if !IsAuthorized(drg, req) {
			t.Error("Test case", i, "failed. Expected authorized = true, but got false.")
		}
	}
}

func TestIsNotAuthorized(t *testing.T) {

	req := &Request{
		Action: APIAction{
			Verb:      "GET",
			Resource:  "pods",
			Name:      "nginx",
			Namespace: "project-1",
		},
	}

	rulesThatDontAuthorize := []api.PolicyRule{
		{
			// Allow POST requests on any resource
			Verbs:     []string{"POST"},
			APIGroups: []string{"*"},
			Resources: []string{"*"},
		},
		{
			// Allow any verb on the nodes resource
			Verbs:     []string{"*"},
			APIGroups: []string{"*"},
			Resources: []string{"nodes"},
		},
		{
			// Allow GET on the nodes resource
			Verbs:     []string{"GET"},
			APIGroups: []string{"*"},
			Resources: []string{"nodes"},
		},
		{
			// Allow POST on the pods resource
			Verbs:     []string{"POST"},
			APIGroups: []string{"*"},
			Resources: []string{"pods"},
		},
	}

	for i, r := range rulesThatDontAuthorize {
		drg := dummyRuleGetter{[]api.PolicyRule{r}}
		auth := IsAuthorized(drg, req)

		if auth {
			t.Error("Test case", i, "failed. Expected authorized = false, but got authorized = true.")
		}
	}
}

func TestIsAuthorizedWithResourceNames(t *testing.T) {

	req := &Request{
		Action: APIAction{
			Verb:      "GET",
			Resource:  "pods",
			Name:      "nginx",
			Namespace: "project-1",
		},
	}

	rulesThatAuthorize := []api.PolicyRule{
		{
			// Allow any request on any resource, where the resource name is nginx
			Verbs:         []string{"*"},
			APIGroups:     []string{"*"},
			Resources:     []string{"*"},
			ResourceNames: []string{"nginx"},
		},
		{
			// Allow GET requests on any resource, where the resource name is nginx
			Verbs:         []string{"GET"},
			APIGroups:     []string{"*"},
			Resources:     []string{"*"},
			ResourceNames: []string{"nginx"},
		},
		{
			// Allow any requests on the pods resource, where the resource name is nginx
			Verbs:         []string{"*"},
			APIGroups:     []string{"*"},
			Resources:     []string{"pods"},
			ResourceNames: []string{"nginx"},
		},
		{
			// Allow GET requests on the pods resource, where the resource name is nginx
			Verbs:         []string{"GET"},
			APIGroups:     []string{"*"},
			Resources:     []string{"pods"},
			ResourceNames: []string{"nginx"},
		},
	}

	for i, r := range rulesThatAuthorize {
		drg := dummyRuleGetter{[]api.PolicyRule{r}}

		if !IsAuthorized(drg, req) {
			t.Error("Test case", i, "failed. Expected authorized = true, but got false.")
		}
	}
}

func TestIsNotAuthorizedWithResourceNames(t *testing.T) {
	req := &Request{
		Action: APIAction{
			Verb:      "GET",
			Resource:  "pods",
			Name:      "nginx",
			Namespace: "project-1",
		},
	}

	rulesThatDontAuth := []api.PolicyRule{
		{
			// Allow any request on resources where the name is "other"
			Verbs:         []string{"*"},
			APIGroups:     []string{"*"},
			Resources:     []string{"*"},
			ResourceNames: []string{"other"},
		},
		{
			// Allow GET requests on resources where the name is "other"
			Verbs:         []string{"GET"},
			APIGroups:     []string{"*"},
			Resources:     []string{"*"},
			ResourceNames: []string{"other"},
		},
		{
			// Allow any requests on "pods" resources where the resource name is "other"
			Verbs:         []string{"*"},
			APIGroups:     []string{"*"},
			Resources:     []string{"pods"},
			ResourceNames: []string{"other"},
		},
		{
			// Allow GET requests on "pods" resources where the resource name is "other"
			Verbs:         []string{"GET"},
			APIGroups:     []string{"*"},
			Resources:     []string{"pods"},
			ResourceNames: []string{"other"},
		},
	}

	for i, r := range rulesThatDontAuth {
		drg := dummyRuleGetter{[]api.PolicyRule{r}}

		if IsAuthorized(drg, req) {
			t.Error("Test case", i, "failed. Expected authorized = false, but got true.")
		}
	}
}

func TestIsAuthorizedNonResourceRequest(t *testing.T) {

	req := &Request{
		Action: APIAction{
			Verb:           "GET",
			NonResourceURL: "/api",
		},
	}

	rulesThatAuthorize := []api.PolicyRule{
		{
			// Allow GET access to the /api endpoint
			Verbs:           []string{"GET"},
			NonResourceURLs: []string{"/api"},
		},
		{
			// Allow GET access to all endpoints
			Verbs:           []string{"GET"},
			NonResourceURLs: []string{"*"},
		},
		{
			// Allow any verb on the /api endpoint
			Verbs:           []string{"*"},
			NonResourceURLs: []string{"/api"},
		},
		{
			// Allow any verb on any endpoint
			Verbs:           []string{"*"},
			NonResourceURLs: []string{"*"},
		},
	}

	for i, r := range rulesThatAuthorize {
		drg := dummyRuleGetter{[]api.PolicyRule{r}}

		if !IsAuthorized(drg, req) {
			t.Error("Test case", i, "failed. Expected authorized = true, but got false.")
		}
	}
}

func TestIsNotAuthorizedNonResourceRequest(t *testing.T) {

	req := &Request{
		Action: APIAction{
			Verb:           "GET",
			NonResourceURL: "/api",
		},
	}

	rulesThatDontAuthorize := []api.PolicyRule{
		{
			// Same URL, different verb
			Verbs:           []string{"POST"},
			NonResourceURLs: []string{"/api"},
		},
		{
			// Same verb, different URL
			Verbs:           []string{"GET"},
			NonResourceURLs: []string{"/other"},
		},
		{
			// All verbs, different URL
			Verbs:           []string{"*"},
			NonResourceURLs: []string{"/other"},
		},
		{
			// Different verb, all URLs
			Verbs:           []string{"POST"},
			NonResourceURLs: []string{"*"},
		},
	}

	for i, r := range rulesThatDontAuthorize {
		drg := dummyRuleGetter{[]api.PolicyRule{r}}

		if IsAuthorized(drg, req) {
			t.Error("Test case", i, "failed. Expected authorized = false, but got true.")
		}
	}
}

func TestIsAuthorizedMultipleRules(t *testing.T) {

	req := &Request{
		Action: APIAction{
			Verb:      "GET",
			Resource:  "pods",
			Name:      "nginx",
			Namespace: "project-1",
		},
	}

	drg := dummyRuleGetter{
		[]api.PolicyRule{
			{
				Verbs:     []string{"POST"},
				APIGroups: []string{"*"},
				Resources: []string{"*"},
			},
			{
				Verbs:     []string{"*"},
				APIGroups: []string{"*"},
				Resources: []string{"nodes"},
			},
			{
				Verbs:     []string{"GET"},
				APIGroups: []string{"*"},
				Resources: []string{"nodes"},
			},
			{
				Verbs:     []string{"POST"},
				APIGroups: []string{"*"},
				Resources: []string{"pods"},
			},
			// This last rule is the one that allows the request
			{
				Verbs:     []string{"GET"},
				APIGroups: []string{"*"},
				Resources: []string{"pods"},
			},
		},
	}

	if !IsAuthorized(drg, req) {
		t.Error("Expected isAuthorized = true, but got false")
	}

}
