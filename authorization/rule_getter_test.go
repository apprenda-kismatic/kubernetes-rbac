package authorization

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/kismatic/kubernetes-rbac/api"
)

type fakeRepo struct {
	bindings            []api.RoleBinding
	roles               []api.Role
	clusterRoles        []api.ClusterRole
	clusterRoleBindings []api.ClusterRoleBinding
}

func (r fakeRepo) GetRoleBinding(name, namespace string) (*api.RoleBinding, error) { return nil, nil }
func (r fakeRepo) CreateRoleBinding(api.RoleBinding) error                         { return nil }
func (r fakeRepo) UpdateRoleBinding(api.RoleBinding) error                         { return nil }
func (r fakeRepo) DeleteRoleBinding(name, namespace string) error                  { return nil }
func (r fakeRepo) CreateRole(api.Role) error                                       { return nil }
func (r fakeRepo) UpdateRole(api.Role) error                                       { return nil }
func (r fakeRepo) DeleteRole(name, namespace string) error                         { return nil }

func (r fakeRepo) ListRoleBindings(namespace string) ([]api.RoleBinding, error) {
	bs := []api.RoleBinding{}
	for _, b := range r.bindings {
		if b.Namespace == namespace {
			bs = append(bs, b)
		}
	}
	return bs, nil
}

func (r fakeRepo) GetRole(name, namespace string) (*api.Role, error) {
	for _, r := range r.roles {
		if r.Name == name && r.Namespace == namespace {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("Role Not found")
}

func (r fakeRepo) GetClusterRole(name string) (*api.ClusterRole, error) {
	for _, r := range r.clusterRoles {
		if r.Name == name {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("Role not found")
}

func (r fakeRepo) ListClusterRoleBindings() ([]api.ClusterRoleBinding, error) {
	return r.clusterRoleBindings, nil
}

func TestRuleGetterNoBindings(t *testing.T) {
	roles := []api.Role{}
	bindings := []api.RoleBinding{}
	clusterRoles := []api.ClusterRole{}
	clusterRoleBindings := []api.ClusterRoleBinding{}
	ruleGetter := RepoRuleGetter{fakeRepo{bindings, roles, clusterRoles, clusterRoleBindings}}

	cases := []struct {
		user  string
		group []string
	}{
		{
			user: "alice",
		},
		{
			user:  "alice",
			group: []string{"group1"},
		},
	}

	for i, c := range cases {
		r, err := ruleGetter.GetApplicableRules(c.user, c.group, "project1")
		if err != nil {
			t.Fatalf("Error getting rules: %v", err)
		}
		if len(r) > 0 {
			t.Error("Test", i, "Expected zero rules, but got some")
		}
	}
}

func TestRuleGetterSingleSubjectBinding(t *testing.T) {
	// Test User Subjects
	aliceSubject := api.Subject{Kind: api.UserKind, Name: "alice"}
	charlieSubject := api.Subject{Kind: api.UserKind, Name: "charlie"}
	// Test Group Subjects
	developersSubject := api.Subject{Kind: api.GroupKind, Name: "developers"}
	marketingSubject := api.Subject{Kind: api.GroupKind, Name: "marketing"}
	// Test Roles
	roles := []api.Role{
		{Name: "role1", Namespace: "project1", Rules: []api.PolicyRule{{Verbs: []string{"role1"}}}},
		{Name: "role2", Namespace: "project1", Rules: []api.PolicyRule{{Verbs: []string{"role2"}}}},
		{Name: "role3", Namespace: "project1", Rules: []api.PolicyRule{{Verbs: []string{"role3"}}}},
		{Name: "role4", Namespace: "project1", Rules: []api.PolicyRule{{Verbs: []string{"role4"}}}},
		{Name: "role5", Namespace: "project1", Rules: []api.PolicyRule{{Verbs: []string{"role5"}}}},
		{Name: "role6", Namespace: "project1", Rules: []api.PolicyRule{{Verbs: []string{"role6"}}}},
	}
	// Test bindings
	bindings := []api.RoleBinding{
		{
			Namespace: "project1",
			Subjects:  []api.Subject{aliceSubject},
			RoleRef:   api.ObjectReference{Kind: api.RoleKind, Namespace: "project1", Name: "role1"},
		},
		{
			Namespace: "project1",
			Subjects:  []api.Subject{aliceSubject},
			RoleRef:   api.ObjectReference{Kind: api.RoleKind, Namespace: "project1", Name: "role2"},
		},
		{
			Namespace: "project1",
			Subjects:  []api.Subject{developersSubject},
			RoleRef:   api.ObjectReference{Kind: api.RoleKind, Namespace: "project1", Name: "role3"},
		},
		{
			Namespace: "project1",
			Subjects:  []api.Subject{developersSubject},
			RoleRef:   api.ObjectReference{Kind: api.RoleKind, Namespace: "project1", Name: "role4"},
		},
		{
			Namespace: "project1",
			Subjects:  []api.Subject{charlieSubject},
			RoleRef:   api.ObjectReference{Kind: api.RoleKind, Namespace: "project1", Name: "role5"},
		},
		{
			Namespace: "project1",
			Subjects:  []api.Subject{marketingSubject},
			RoleRef:   api.ObjectReference{Kind: api.RoleKind, Namespace: "project1", Name: "role6"},
		},
	}

	clusterRoles := []api.ClusterRole{}
	clusterRoleBindings := []api.ClusterRoleBinding{}
	ruleGetter := RepoRuleGetter{fakeRepo{bindings, roles, clusterRoles, clusterRoleBindings}}

	cases := []struct {
		user          string
		groups        []string
		expectedRules []api.PolicyRule
	}{
		{
			user:          "alice",
			expectedRules: []api.PolicyRule{{Verbs: []string{"role1"}}, {Verbs: []string{"role2"}}},
		},
		{
			user:          "bob",
			expectedRules: []api.PolicyRule{},
		},
		{
			user:          "alice",
			groups:        []string{"developers"},
			expectedRules: []api.PolicyRule{{Verbs: []string{"role1"}}, {Verbs: []string{"role2"}}, {Verbs: []string{"role3"}}, {Verbs: []string{"role4"}}},
		},
		{
			user:          "alice",
			groups:        []string{"accounting"},
			expectedRules: []api.PolicyRule{{Verbs: []string{"role1"}}, {Verbs: []string{"role2"}}},
		},
		{
			user:          "alice",
			groups:        []string{"accounting", "developers"},
			expectedRules: []api.PolicyRule{{Verbs: []string{"role1"}}, {Verbs: []string{"role2"}}, {Verbs: []string{"role3"}}, {Verbs: []string{"role4"}}},
		},
		{
			user:          "bob",
			groups:        []string{"developers"},
			expectedRules: []api.PolicyRule{{Verbs: []string{"role3"}}, {Verbs: []string{"role4"}}},
		},
		{
			user:          "bob",
			groups:        []string{"accouting"},
			expectedRules: []api.PolicyRule{},
		},
		{
			user:          "bob",
			groups:        []string{"developers", "accounting"},
			expectedRules: []api.PolicyRule{{Verbs: []string{"role3"}}, {Verbs: []string{"role4"}}},
		},
	}

	for i, c := range cases {
		rules, err := ruleGetter.GetApplicableRules(c.user, c.groups, "project1")
		if err != nil {
			t.Fatalf("Case %d: Error getting rules: %v", i, err)
		}

		if !reflect.DeepEqual(c.expectedRules, rules) {
			t.Logf("Expected: %+v\nGot: %+v", c.expectedRules, rules)
			t.Errorf("Case %d: Expected policy rules were not equal to the obtained applicable rules", i)
		}
	}
}

func TestRuleGetterMultiUserBinding(t *testing.T) {
	// Test User Subjects
	aliceSubject := api.Subject{Kind: api.UserKind, Name: "alice"}
	charlieSubject := api.Subject{Kind: api.UserKind, Name: "charlie"}
	// Test Roles
	roles := []api.Role{
		{Name: "role1", Namespace: "project1", Rules: []api.PolicyRule{{Verbs: []string{"role1"}}}},
		{Name: "role2", Namespace: "project1", Rules: []api.PolicyRule{{Verbs: []string{"role2"}}}},
	}
	// Test bindings
	bindings := []api.RoleBinding{
		{
			Namespace: "project1",
			Subjects:  []api.Subject{aliceSubject, charlieSubject},
			RoleRef:   api.ObjectReference{Kind: api.RoleKind, Namespace: "project1", Name: "role1"},
		},
	}
	clusterRoles := []api.ClusterRole{}
	clusterRoleBindings := []api.ClusterRoleBinding{}
	ruleGetter := RepoRuleGetter{fakeRepo{bindings, roles, clusterRoles, clusterRoleBindings}}

	cases := []struct {
		user          string
		expectedRules []api.PolicyRule
	}{
		{
			user:          "alice",
			expectedRules: []api.PolicyRule{{Verbs: []string{"role1"}}},
		},
		{
			user:          "charlie",
			expectedRules: []api.PolicyRule{{Verbs: []string{"role1"}}},
		},
	}

	for i, c := range cases {
		ar, err := ruleGetter.GetApplicableRules(c.user, []string{}, "project1")
		if err != nil {
			t.Fatalf("Case %d: Error getting rules: %v", i, err)
		}

		if !reflect.DeepEqual(c.expectedRules, ar) {
			t.Logf("Expected: %+v\nGot: %+v", c.expectedRules, ar)
			t.Errorf("Case %d: Expected policy rules were not equal to the obtained applicable rules", i)
		}
	}
}

func TestRuleGetterMultiGroupBinding(t *testing.T) {
	// Test User Subjects
	aliceSubject := api.Subject{Kind: api.UserKind, Name: "alice"}
	// charlieSubject := api.Subject{Kind: api.UserKind, Name: "charlie"}
	// Test Group Subjects
	developersSubject := api.Subject{Kind: api.GroupKind, Name: "developers"}
	marketingSubject := api.Subject{Kind: api.GroupKind, Name: "marketing"}
	// Test Roles
	roles := []api.Role{
		{Name: "role1", Namespace: "project1", Rules: []api.PolicyRule{{Verbs: []string{"role1"}}}},
		{Name: "role2", Namespace: "project1", Rules: []api.PolicyRule{{Verbs: []string{"role2"}}}},
	}
	// Test bindings
	bindings := []api.RoleBinding{
		{
			Namespace: "project1",
			Subjects:  []api.Subject{aliceSubject, developersSubject, marketingSubject},
			RoleRef:   api.ObjectReference{Kind: api.RoleKind, Namespace: "project1", Name: "role1"},
		},
	}

	clusterRoles := []api.ClusterRole{}
	clusterRoleBindings := []api.ClusterRoleBinding{}
	ruleGetter := RepoRuleGetter{fakeRepo{bindings, roles, clusterRoles, clusterRoleBindings}}

	cases := []struct {
		user          string
		groups        []string
		expectedRules []api.PolicyRule
	}{
		{
			user:          "bob",
			groups:        []string{"developers"},
			expectedRules: []api.PolicyRule{{Verbs: []string{"role1"}}},
		},
		{
			user:          "bob",
			groups:        []string{"marketing"},
			expectedRules: []api.PolicyRule{{Verbs: []string{"role1"}}},
		},
		{
			user:          "alice",
			groups:        []string{},
			expectedRules: []api.PolicyRule{{Verbs: []string{"role1"}}},
		},
	}

	for i, c := range cases {
		ar, err := ruleGetter.GetApplicableRules(c.user, c.groups, "project1")
		if err != nil {
			t.Fatalf("Case %d: Error getting rules: %v", i, err)
		}

		if !reflect.DeepEqual(c.expectedRules, ar) {
			t.Logf("Expected: %+v\nGot: %+v", c.expectedRules, ar)
			t.Errorf("Case %d: Expected policy rules were not equal to the obtained applicable rules", i)
		}
	}
}

func TestRuleGetterWildcardUsers(t *testing.T) {
	// Test Roles
	roles := []api.Role{
		{Name: "role1", Namespace: "project1", Rules: []api.PolicyRule{{Verbs: []string{"role1"}}}},
	}
	// Test bindings
	bindings := []api.RoleBinding{
		{
			Namespace: "project1",
			Subjects:  []api.Subject{{Kind: "User", Name: "*"}},
			RoleRef:   api.ObjectReference{Kind: api.RoleKind, Namespace: "project1", Name: "role1"},
		},
	}

	clusterRoles := []api.ClusterRole{}
	clusterRoleBindings := []api.ClusterRoleBinding{}
	ruleGetter := RepoRuleGetter{fakeRepo{bindings, roles, clusterRoles, clusterRoleBindings}}

	ar, err := ruleGetter.GetApplicableRules("alice", []string{}, "project1")
	if err != nil {
		t.Errorf("Error getting rules: %v", err)
	}
	if !reflect.DeepEqual(ar, roles[0].Rules) {
		t.Errorf("Expected rules did not match the obtained rules")
	}
}

func TestClusterRoleGetNoNamespace(t *testing.T) {
	bindings := []api.RoleBinding{}
	roles := []api.Role{}
	clusterRoles := []api.ClusterRole{
		{
			Name:  "role1",
			Rules: []api.PolicyRule{{Verbs: []string{"role1"}}},
		},
	}
	clusterRoleBindings := []api.ClusterRoleBinding{
		{
			Name:     "cluster1",
			Subjects: []api.Subject{{Kind: "User", Name: "alice"}},
			RoleRef:  api.ObjectReference{Kind: api.ClusterRoleKind, Name: "role1"},
		},
	}
	ruleGetter := RepoRuleGetter{fakeRepo{bindings, roles, clusterRoles, clusterRoleBindings}}

	ar, err := ruleGetter.GetApplicableRules("alice", []string{}, "")
	if err != nil {
		t.Errorf("Error getting rules: %v", err)
	}
	if !reflect.DeepEqual(ar, clusterRoles[0].Rules) {
		t.Errorf("Expected rules did not match the obtained rules")
	}
}

func TestClusterRoleGetWithNamespace(t *testing.T) {
	bindings := []api.RoleBinding{}
	roles := []api.Role{}
	clusterRoles := []api.ClusterRole{
		{
			Name:  "role1",
			Rules: []api.PolicyRule{{Verbs: []string{"role1"}}},
		},
	}
	clusterRoleBindings := []api.ClusterRoleBinding{
		{
			Name:     "cluster1",
			Subjects: []api.Subject{{Kind: "User", Name: "alice"}},
			RoleRef:  api.ObjectReference{Kind: api.ClusterRoleKind, Name: "role1"},
		},
	}
	ruleGetter := RepoRuleGetter{fakeRepo{bindings, roles, clusterRoles, clusterRoleBindings}}

	ar, err := ruleGetter.GetApplicableRules("alice", []string{}, "some-project")
	if err != nil {
		t.Errorf("Error getting rules: %v", err)
	}
	if !reflect.DeepEqual(ar, clusterRoles[0].Rules) {
		t.Errorf("Expected rules did not match the obtained rules")
	}
}

func TestClusterRoleNoBinding(t *testing.T) {
	bindings := []api.RoleBinding{}
	roles := []api.Role{}
	clusterRoles := []api.ClusterRole{
		{
			Name:  "role1",
			Rules: []api.PolicyRule{{Verbs: []string{"role1"}}},
		},
	}
	clusterRoleBindings := []api.ClusterRoleBinding{
		{
			Name:     "cluster1",
			Subjects: []api.Subject{{Kind: "User", Name: "bob"}},
			RoleRef:  api.ObjectReference{Kind: api.ClusterRoleKind, Name: "role1"},
		},
	}
	ruleGetter := RepoRuleGetter{fakeRepo{bindings, roles, clusterRoles, clusterRoleBindings}}
	ar, err := ruleGetter.GetApplicableRules("alice", []string{}, "some-project")
	if err != nil {
		t.Errorf("Error getting rules: %v", err)
	}

	// Bob should have no rules
	if !reflect.DeepEqual(ar, []api.PolicyRule{}) {
		t.Errorf("Expected rules did not match the obtained rules")
	}
}

func TestClusterRoleDoesNotExist(t *testing.T) {
	bindings := []api.RoleBinding{}
	roles := []api.Role{}
	clusterRoles := []api.ClusterRole{}
	clusterRoleBindings := []api.ClusterRoleBinding{
		{
			Name:     "cluster1",
			Subjects: []api.Subject{{Kind: "User", Name: "alice"}},
			RoleRef:  api.ObjectReference{Kind: api.ClusterRoleKind, Name: "role1"},
		},
	}
	ruleGetter := RepoRuleGetter{fakeRepo{bindings, roles, clusterRoles, clusterRoleBindings}}
	_, err := ruleGetter.GetApplicableRules("alice", []string{}, "some-project")
	if err == nil {
		t.Errorf("Expected an error, but got nil")
	}
}

func TestClusterRoleRefFromRoleBinding(t *testing.T) {
	bindings := []api.RoleBinding{
		{
			Namespace: "project1",
			Subjects:  []api.Subject{{Kind: "User", Name: "alice"}},
			RoleRef:   api.ObjectReference{Kind: api.ClusterRoleKind, Name: "role1"},
		},
	}
	roles := []api.Role{}
	clusterRoles := []api.ClusterRole{
		{
			Name:  "role1",
			Rules: []api.PolicyRule{{Verbs: []string{"role1"}}},
		},
	}
	clusterRoleBindings := []api.ClusterRoleBinding{}
	ruleGetter := RepoRuleGetter{fakeRepo{bindings, roles, clusterRoles, clusterRoleBindings}}
	ar, err := ruleGetter.GetApplicableRules("alice", []string{}, "project1")
	if err != nil {
		t.Errorf("Error getting applicable rules: %v", err)
	}

	if !reflect.DeepEqual(ar, clusterRoles[0].Rules) {
		t.Errorf("Expected rules are not equal to the obtained rules")
	}
}

func TestClusterRoleFromRoleBindingWrongNamespace(t *testing.T) {
	bindings := []api.RoleBinding{
		{
			Namespace: "project1",
			Subjects:  []api.Subject{{Kind: "User", Name: "alice"}},
			RoleRef:   api.ObjectReference{Kind: api.ClusterRoleKind, Name: "role"},
		},
	}
	clusterRoles := []api.ClusterRole{
		{
			Name:  "role1",
			Rules: []api.PolicyRule{{Verbs: []string{"role1"}}},
		},
	}
	crb := []api.ClusterRoleBinding{}
	roles := []api.Role{}
	ruleGetter := RepoRuleGetter{fakeRepo{bindings, roles, clusterRoles, crb}}
	ar, err := ruleGetter.GetApplicableRules("alice", []string{}, "someOtherNamespace")
	if err != nil {
		t.Errorf("Error getting applicale rules: %v", err)
	}
	if !reflect.DeepEqual(ar, []api.PolicyRule{}) {
		t.Errorf("Expected rules are not equal to obtained rules")
	}
}
