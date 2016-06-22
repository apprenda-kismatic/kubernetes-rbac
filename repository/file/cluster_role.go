package file

import (
	"fmt"

	"github.com/kismatic/kubernetes-rbac/api"
)

// GetClusterRole with the given name
func (fr *FlatFileRepository) GetClusterRole(name string) (*api.ClusterRole, error) {
	fr.RLock()
	defer fr.RUnlock()
	p, err := fr.readPolicy()
	if err != nil {
		return nil, err
	}
	for _, cr := range p.ClusterRoles {
		if cr.Name == name {
			return &cr, nil
		}
	}
	return nil, fmt.Errorf("Cluster role '%s' does not exist", name)
}
