package file

import (
	"reflect"
	"testing"

	"github.com/kismatic/kubernetes-rbac/api"
	"github.com/kismatic/kubernetes-rbac/repository"
)

var testRoleBinding = api.RoleBinding{
	Name:      "name",
	Namespace: "namespace",
	Subjects:  []api.Subject{{Kind: "User", Name: "Bob"}},
	RoleRef:   api.ObjectReference{Kind: "Role", Name: "admin", Namespace: "foo"},
}

func createRepoWithRoleBinding(r api.RoleBinding) (repository.PolicyRepository, error) {
	file := getTestRepoFile()
	repo, err := Create(file)
	if err != nil {
		return nil, err
	}
	if err := repo.CreateRoleBinding(r); err != nil {
		return nil, err
	}
	return repo, nil
}

func TestCreateRoleBinding(t *testing.T) {
	repo, err := createRepoWithRoleBinding(testRoleBinding)
	if err != nil {
		t.Fatalf("Error creating repo: %v", err)
	}

	got, err := repo.GetRoleBinding(testRoleBinding.Name, testRoleBinding.Namespace)
	if err != nil {
		t.Errorf("Error getting role binding: %v", err)
	}

	if !reflect.DeepEqual(testRoleBinding, *got) {
		t.Errorf("Obtained role binding does not equal created role")
	}

	if err = deleteRepo(); err != nil {
		t.Fatal(err)
	}
}

func TestCreateExistingRoleBinding(t *testing.T) {
	repo, err := createRepoWithRoleBinding(testRoleBinding)
	if err != nil {
		t.Fatalf("Error creating repo: %v", err)
	}

	if err = repo.CreateRoleBinding(testRoleBinding); err == nil {
		t.Errorf("Expected error when creating role binding that already exists")
	}

	if err = deleteRepo(); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateRoleBinding(t *testing.T) {

	rb := testRoleBinding
	repo, err := createRepoWithRoleBinding(rb)
	if err != nil {
		t.Fatalf("Error creating repo: %v", err)
	}

	rb.Subjects = append(rb.Subjects, api.Subject{Kind: "User", Name: "Alice"})

	if err := repo.UpdateRoleBinding(rb); err != nil {
		t.Errorf("Error updating role binding: %v", err)
	}

	got, err := repo.GetRoleBinding(rb.Name, rb.Namespace)
	if err != nil {
		t.Errorf("Error getting role binding: %v", err)
	}

	if !reflect.DeepEqual(rb, *got) {
		t.Errorf("Obtained role binding does not equal updated role binding")
	}

	if err = deleteRepo(); err != nil {
		t.Fatal(err)
	}

}

func TestUpdateNonExistentRoleBinding(t *testing.T) {
	repo, err := createRepoWithRoleBinding(testRoleBinding)
	if err != nil {
		t.Fatalf("Error creating repo: %v", err)
	}

	rb := testRoleBinding
	rb.Name = "SomeOtherBinding"

	if err := repo.UpdateRoleBinding(rb); err == nil {
		t.Error("Expected error when updating role binding that does not exist")
	}

	if err = deleteRepo(); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteRoleBinding(t *testing.T) {
	repo, err := createRepoWithRoleBinding(testRoleBinding)
	if err != nil {
		t.Fatalf("Error creating repo: %v", err)
	}

	rbName := testRoleBinding.Name
	rbNamespace := testRoleBinding.Namespace

	if err = repo.DeleteRoleBinding(rbName, rbNamespace); err != nil {
		t.Errorf("Error deleting role binding: %v", err)
	}

	if _, err := repo.GetRoleBinding(rbName, rbNamespace); err == nil {
		t.Errorf("Did not get an error when getting a role binding that does not exist")
	}

	if err = deleteRepo(); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteNonExistentRoleBinding(t *testing.T) {
	repo, err := createRepoWithRoleBinding(testRoleBinding)
	if err != nil {
		t.Fatalf("Error creating repo: %v", err)
	}

	if err = repo.DeleteRoleBinding("otherRoleBinding", "other"); err == nil {
		t.Error("Expected error when deleting role binding that does not exist")
	}

	if err = deleteRepo(); err != nil {
		t.Fatal(err)
	}
}
