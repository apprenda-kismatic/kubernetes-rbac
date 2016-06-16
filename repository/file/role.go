package file

import (
	"errors"
	"fmt"

	"github.com/kismatic/kubernetes-rbac/api"
)

// GetRole with the given name and namespace.
func (fr *FlatFileRepository) GetRole(name, namespace string) (*api.Role, error) {
	fr.RLock()
	defer fr.RUnlock()

	p, err := fr.readPolicy()
	if err != nil {
		return nil, err
	}

	i := findRoleIndex(p.Roles, name, namespace)

	if i >= 0 {
		return &p.Roles[i], nil
	}

	return nil, fmt.Errorf("Role with name '%s' in namespace '%s' does not exist", name, namespace)
}

// CreateRole the given role.
func (fr *FlatFileRepository) CreateRole(role api.Role) error {
	fr.Lock()
	defer fr.Unlock()

	p, err := fr.readPolicy()
	if err != nil {
		return err
	}

	i := findRoleIndex(p.Roles, role.Name, role.Namespace)
	if i >= 0 {
		return errors.New("Role already exists")
	}

	p.Roles = append(p.Roles, role)

	return fr.writePolicy(p)
}

// UpdateRole the given role.
func (fr *FlatFileRepository) UpdateRole(role api.Role) error {
	fr.Lock()
	defer fr.Unlock()

	p, err := fr.readPolicy()
	if err != nil {
		return err
	}

	i := findRoleIndex(p.Roles, role.Name, role.Namespace)
	if i < 0 {
		return fmt.Errorf("Attempting to update role that does not exist.")
	}

	p.Roles[i] = role

	return fr.writePolicy(p)
}

// DeleteRole with the given name and namespace.
func (fr *FlatFileRepository) DeleteRole(name, namespace string) error {
	fr.Lock()
	defer fr.Unlock()

	p, err := fr.readPolicy()
	if err != nil {
		return err
	}

	i := findRoleIndex(p.Roles, name, namespace)
	if i < 0 {
		return fmt.Errorf("Attempting to delete role that does not exist.")
	}

	p.Roles = append(p.Roles[:i], p.Roles[i+1:]...)

	return fr.writePolicy(p)
}

func findRoleIndex(roles []api.Role, name, namespace string) int {
	for i, r := range roles {
		if r.Name == name && r.Namespace == namespace {
			return i
		}
	}
	return -1
}
