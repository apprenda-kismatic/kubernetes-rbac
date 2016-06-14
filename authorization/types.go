package authorization

import "github.com/kismatic/kubernetes-rbac/api"

// APIAction is the action that is being authorized on the given resource.
type APIAction struct {
	// Verb is the Kubernetes resource API verb.
	Verb string
	// APIGroup is the name of the Kubernetes API group that contains the resource.
	APIGroup string
	// Resource is the name of the Kubernetes resource being accessed.
	Resource string
	// Subresource is the name of the subresource.
	Subresource string
	// Name is the name of the resource that receives the action.
	Name string
	// Namespace is the namespace of the resource that receives the action.
	Namespace string
	// NonResourceURL is the URL path of a non-resource request (e.g. "/api").
	NonResourceURL string
}

// Request to be authorized according to defined policy.
type Request struct {
	// User is the name of the user performing the request.
	User string
	// Groups is a list of group names that the user belongs to.
	Groups []string
	// Action is what the user is trying to do in this request.
	Action APIAction
}

type PolicyRuleGetter interface {
	// GetApplicableRules gets the policy rules that apply to the given user/group in the
	// specified namespace.
	GetApplicableRules(user string, groups []string, namespace string) []api.PolicyRule
}
