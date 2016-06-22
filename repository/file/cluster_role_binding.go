package file

import "github.com/kismatic/kubernetes-rbac/api"

// ListClusterRoleBindings returns a list of all cluster role bindings
func (fr *FlatFileRepository) ListClusterRoleBindings() ([]api.ClusterRoleBinding, error) {
	fr.RLock()
	defer fr.RUnlock()
	p, err := fr.readPolicy()
	if err != nil {
		return nil, err
	}
	return p.ClusterRoleBindings, nil
}
