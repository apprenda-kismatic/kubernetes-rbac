package authorization

import "github.com/kismatic/kubernetes-rbac/api"

// RuleValidator determines if the APIAction is allowed by a PolicyRule
type RuleValidator func(api.PolicyRule, APIAction) bool

// IsAuthorized determines whether the policy allows the action requested by the user
func IsAuthorized(ruleGetter PolicyRuleGetter, ar *Request) bool {

	// Get all the PolicyRules that apply to the user in the given namespace
	rules := ruleGetter.GetApplicableRules(ar.User, ar.Groups, ar.Action.Namespace)

	// Depending on the request, we might be validating access to an API resource, or to
	// a "NonResource" URL.
	var validateRule RuleValidator = isResourceActionAllowed
	if ar.Action.NonResourceURL != "" {
		validateRule = isNonResourceAccessAllowed
	}

	// Find a rule that allows the requested action
	for _, r := range rules {
		if validateRule(r, ar.Action) {
			return true
		}
	}

	return false
}

func isResourceActionAllowed(rule api.PolicyRule, action APIAction) bool {
	allowsGroup := contains(rule.APIGroups, api.APIGroupAll) || contains(rule.APIGroups, action.APIGroup)
	allowsVerb := contains(rule.Verbs, api.VerbAll) || contains(rule.Verbs, action.Verb)
	allowsResource := contains(rule.Resources, api.ResourceAll) || contains(rule.Resources, action.Resource)

	// Handle resource names whitelist
	allowsResourceName := false
	if len(rule.ResourceNames) == 0 { // No whitelist defined
		allowsResourceName = true
	} else {
		// Verify resource name is in whitelist
		allowsResourceName = contains(rule.ResourceNames, action.Name)
	}

	return allowsGroup && allowsVerb && allowsResource && allowsResourceName
}

func isNonResourceAccessAllowed(rule api.PolicyRule, action APIAction) bool {
	allowsVerb := contains(rule.Verbs, api.VerbAll) || contains(rule.Verbs, action.Verb)
	allowsNonResource := contains(rule.NonResourceURLs, api.NonResourceAll) || contains(rule.NonResourceURLs, action.NonResourceURL)

	return allowsVerb && allowsNonResource
}

func contains(set []string, value string) bool {
	for _, e := range set {
		if e == value {
			return true
		}
	}
	return false
}
