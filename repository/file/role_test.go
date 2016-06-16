package file

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/kismatic/kubernetes-rbac/api"
	"github.com/kismatic/kubernetes-rbac/repository"
)

var testRole = api.Role{
	Name:      "SomeRole",
	Namespace: "default",
	Rules: []api.PolicyRule{
		{
			Verbs: []string{"*"},
		},
	},
}

func TestCreateRole(t *testing.T) {

	repo, err := createRepoWithRole(testRole)
	if err != nil {
		t.Fatalf("Error creating repo: %v", err)
	}

	got, err := repo.GetRole(testRole.Name, testRole.Namespace)
	if err != nil {
		t.Errorf("Error getting role: %v", err)
	}

	if !reflect.DeepEqual(testRole, *got) {
		t.Errorf("Obtained role does not equal created role")
	}

	if err = deleteRepo(); err != nil {
		t.Fatal(err)
	}
}

func TestCreateExistingRole(t *testing.T) {
	repo, err := createRepoWithRole(testRole)
	if err != nil {
		t.Fatalf("Error creating repo: %v", err)
	}

	if err = repo.CreateRole(testRole); err == nil {
		t.Errorf("Expected error when creating role that already exists")
	}

	if err = deleteRepo(); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateRole(t *testing.T) {
	r := testRole
	repo, err := createRepoWithRole(r)
	if err != nil {
		t.Fatalf("Error creating repo: %v", err)
	}

	r.Rules = []api.PolicyRule{
		{
			Verbs: []string{"GET"},
		},
	}

	if err := repo.UpdateRole(r); err != nil {
		t.Errorf("Error updating role: %v", err)
	}

	got, err := repo.GetRole(r.Name, r.Namespace)
	if err != nil {
		t.Errorf("Error getting role: %v", err)
	}

	if !reflect.DeepEqual(r, *got) {
		t.Errorf("Obtained role does not equal updated role")
	}

	if err = deleteRepo(); err != nil {
		t.Fatal(err)
	}

}

func TestUpdateNonExistentRole(t *testing.T) {
	r := testRole
	repo, err := createRepoWithRole(r)
	if err != nil {
		t.Fatalf("Error creating repo: %v", err)
	}

	r.Name = "otherRole"

	if err := repo.UpdateRole(r); err == nil {
		t.Error("Expected error when updating role that does not exist")
	}

	if err = deleteRepo(); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteRole(t *testing.T) {
	repo, err := createRepoWithRole(testRole)
	if err != nil {
		t.Fatalf("Error creating repo: %v", err)
	}

	if err = repo.DeleteRole(testRole.Name, testRole.Namespace); err != nil {
		t.Errorf("Error deleting role: %v", err)
	}

	if _, err := repo.GetRole(testRole.Name, testRole.Namespace); err == nil {
		t.Errorf("Did not get an error when getting a role that does not exist")
	}

	if err = deleteRepo(); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteNonExistentRole(t *testing.T) {
	repo, err := createRepoWithRole(testRole)
	if err != nil {
		t.Fatalf("Error creating repo: %v", err)
	}

	if err = repo.DeleteRole("otherRole", testRole.Namespace); err == nil {
		t.Error("Expected error when deleting role that does not exist")
	}

	if err = deleteRepo(); err != nil {
		t.Fatal(err)
	}
}

func getTestRepoFile() string {
	return filepath.Join(os.TempDir(), "policy-repo.json")
}

func createRepoWithRole(r api.Role) (repository.PolicyRepository, error) {
	file := getTestRepoFile()
	repo, err := Create(file)
	if err != nil {
		return nil, err
	}
	if err := repo.CreateRole(r); err != nil {
		return nil, err
	}
	return repo, nil
}

func deleteRepo() error {
	f := getTestRepoFile()
	if err := os.Remove(f); err != nil {
		return err
	}
	return nil
}
