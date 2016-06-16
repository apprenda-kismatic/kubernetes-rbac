package authorization

import (
	"fmt"
	"log"

	"github.com/kismatic/kubernetes-rbac/api"
	"github.com/kismatic/kubernetes-rbac/repository"
)

// PolicyRuleGetter gets policy rules
type PolicyRuleGetter interface {
	// GetApplicableRules gets the policy rules that apply to the given user/group in the
	// specified namespace.
	GetApplicableRules(user string, groups []string, namespace string) ([]api.PolicyRule, error)
}

// RepoRuleGetter gets rules from policy repository
type RepoRuleGetter struct {
	Repo repository.PolicyRepository
}

// GetApplicableRules gets the policy rules that apply to the given user/group in the
// specified namespace.
func (g *RepoRuleGetter) GetApplicableRules(user string, groups []string, namespace string) ([]api.PolicyRule, error) {
	// Get all bindings in the namespace
	rbs, err := g.Repo.ListRoleBindings(namespace)
	if err != nil {
		return nil, err
	}
	rules := []api.PolicyRule{}

	// Check if the user is contained in any of the role bindings
	for _, b := range rbs {
		for _, s := range b.Subjects {
			// Add the rules if the subject matches the user being authorized
			if subjectMatches(s, user, groups) {
				role, err := g.Repo.GetRole(b.RoleRef.Name, b.RoleRef.Namespace)
				if err != nil {
					return nil, err
				}
				rules = append(rules, role.Rules...)
			}
		}
	}
	return rules, nil
}

// returns true if the subject matches the user/groups
func subjectMatches(s api.Subject, user string, groups []string) bool {
	switch s.Kind {
	case api.UserKind:
		return s.Name == user || s.Name == api.UserAll
	case api.GroupKind:
		return contains(groups, s.Name)
	case api.ServiceAccountKind:
		if s.Namespace == "" {
			log.Printf("ERROR: ServiceAccount subject with no namespace defined. Subject name: %s", s.Name)
			return false
		}
		return user == fmt.Sprintf("system:service:%s:%s", s.Name, s.Namespace)
	}
	return false
}
