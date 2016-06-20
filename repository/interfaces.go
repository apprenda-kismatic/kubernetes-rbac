package repository

import "github.com/kismatic/kubernetes-rbac/api"

// PolicyRepository provides access to the persisted policy objects
type PolicyRepository interface {
	RoleBindingRepository
	RoleRepository
	ClusterRoleRepository
	ClusterRoleBindingRepository
}

// RoleRepository provides access to persisted roles.
type RoleRepository interface {
	// Get the role with the given name in the given namespace.
	GetRole(name, namespace string) (*api.Role, error)
	// Create the given role.
	CreateRole(api.Role) error
	// Update the given role.
	UpdateRole(api.Role) error
	// Delete the role with the given name and namespace.
	DeleteRole(name, namespace string) error
}

// RoleBindingRepository provides access to persisted role bindings.
type RoleBindingRepository interface {
	// Get the role binding with the given name and namespace.
	GetRoleBinding(name, namespace string) (*api.RoleBinding, error)
	// Create the given role binding.
	CreateRoleBinding(api.RoleBinding) error
	// Update the given role binding.
	UpdateRoleBinding(api.RoleBinding) error
	// Delete the role binding with the given name and namespace.
	DeleteRoleBinding(name, namespace string) error

	// ListRoleBindings in the given namespace
	ListRoleBindings(namespace string) ([]api.RoleBinding, error)
}

// ClusterRoleRepository provides access to persisted cluster roles.
type ClusterRoleRepository interface {
	// Get the role with the given name in the given namespace.
	GetClusterRole(name string) (*api.ClusterRole, error)
}

// ClusterRoleBindingRepository provides access to persisted cluster role bindings.
type ClusterRoleBindingRepository interface {
	ListClusterRoleBindings() ([]api.ClusterRoleBinding, error)
}
