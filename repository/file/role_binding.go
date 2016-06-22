package file

import (
	"fmt"

	"github.com/kismatic/kubernetes-rbac/api"
)

// GetRoleBinding with the given name and namespace
func (fr *FlatFileRepository) GetRoleBinding(name, namespace string) (*api.RoleBinding, error) {
	fr.RLock()
	defer fr.RUnlock()

	p, err := fr.readPolicy()
	if err != nil {
		return nil, err
	}

	i := findRoleBindingIndex(p.RoleBindings, name, namespace)
	if i < 0 {
		return nil, fmt.Errorf("Role binding with name '%s' in namespace '%s' does not exist", name, namespace)
	}

	return &p.RoleBindings[i], nil
}

// CreateRoleBinding in the repository
func (fr *FlatFileRepository) CreateRoleBinding(rb api.RoleBinding) error {
	fr.Lock()
	defer fr.Unlock()

	p, err := fr.readPolicy()
	if err != nil {
		return err
	}

	i := findRoleBindingIndex(p.RoleBindings, rb.Name, rb.Namespace)
	if i >= 0 {
		return fmt.Errorf("Role Binding with name '%s' in namespace '%s' already exists", rb.Name, rb.Namespace)
	}

	p.RoleBindings = append(p.RoleBindings, rb)

	return fr.writePolicy(p)
}

// UpdateRoleBinding with the new role binding
func (fr *FlatFileRepository) UpdateRoleBinding(rb api.RoleBinding) error {
	fr.Lock()
	defer fr.Unlock()

	p, err := fr.readPolicy()
	if err != nil {
		return err
	}

	i := findRoleBindingIndex(p.RoleBindings, rb.Name, rb.Namespace)
	if i < 0 {
		return fmt.Errorf("Attempting to update role that does not exist")
	}

	p.RoleBindings[i] = rb

	return fr.writePolicy(p)
}

// DeleteRoleBinding with the given name and namespace
func (fr *FlatFileRepository) DeleteRoleBinding(name, namespace string) error {
	fr.Lock()
	defer fr.Unlock()

	p, err := fr.readPolicy()
	if err != nil {
		return err
	}

	i := findRoleBindingIndex(p.RoleBindings, name, namespace)
	if i < 0 {
		return fmt.Errorf("Attempting to delete role binding that does not exist.")
	}

	p.RoleBindings = append(p.RoleBindings[:i], p.RoleBindings[i+1:]...)

	return fr.writePolicy(p)
}

// ListRoleBindings in the given namespace
func (fr *FlatFileRepository) ListRoleBindings(namespace string) ([]api.RoleBinding, error) {
	fr.RLock()
	defer fr.RUnlock()

	p, err := fr.readPolicy()
	if err != nil {
		return nil, err
	}

	bindings := []api.RoleBinding{}
	for _, b := range p.RoleBindings {
		if b.Namespace == namespace {
			bindings = append(bindings, b)
		}
	}

	return bindings, nil
}

func findRoleBindingIndex(bindings []api.RoleBinding, name, namespace string) int {
	for i, rb := range bindings {
		if rb.Name == name && rb.Namespace == namespace {
			return i
		}
	}
	return -1
}
