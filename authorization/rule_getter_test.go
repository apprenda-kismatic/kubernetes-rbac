package authorization

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/kismatic/kubernetes-rbac/api"
)

type fakeRepo struct {
	bindings []api.RoleBinding
	roles    []api.Role
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

func TestRuleGetterNoBindings(t *testing.T) {
	roles := []api.Role{}
	bindings := []api.RoleBinding{}
	ruleGetter := RepoRuleGetter{fakeRepo{bindings, roles}}

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
			RoleRef:   api.ObjectReference{Namespace: "project1", Name: "role1"},
		},
		{
			Namespace: "project1",
			Subjects:  []api.Subject{aliceSubject},
			RoleRef:   api.ObjectReference{Namespace: "project1", Name: "role2"},
		},
		{
			Namespace: "project1",
			Subjects:  []api.Subject{developersSubject},
			RoleRef:   api.ObjectReference{Namespace: "project1", Name: "role3"},
		},
		{
			Namespace: "project1",
			Subjects:  []api.Subject{developersSubject},
			RoleRef:   api.ObjectReference{Namespace: "project1", Name: "role4"},
		},
		{
			Namespace: "project1",
			Subjects:  []api.Subject{charlieSubject},
			RoleRef:   api.ObjectReference{Namespace: "project1", Name: "role5"},
		},
		{
			Namespace: "project1",
			Subjects:  []api.Subject{marketingSubject},
			RoleRef:   api.ObjectReference{Namespace: "project1", Name: "role6"},
		},
	}

	ruleGetter := RepoRuleGetter{fakeRepo{bindings, roles}}

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
			RoleRef:   api.ObjectReference{Namespace: "project1", Name: "role1"},
		},
	}
	ruleGetter := RepoRuleGetter{fakeRepo{bindings, roles}}

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
			RoleRef:   api.ObjectReference{Namespace: "project1", Name: "role1"},
		},
	}

	ruleGetter := RepoRuleGetter{fakeRepo{bindings, roles}}

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
			RoleRef:   api.ObjectReference{Namespace: "project1", Name: "role1"},
		},
	}

	ruleGetter := RepoRuleGetter{fakeRepo{bindings, roles}}

	ar, err := ruleGetter.GetApplicableRules("alice", []string{}, "project1")
	if err != nil {
		t.Errorf("Error getting rules: %v", err)
	}
	if !reflect.DeepEqual(ar, roles[0].Rules) {
		t.Errorf("Expected rules did not match the obtained rules")
	}
}
