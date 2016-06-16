package file

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sync"

	"github.com/kismatic/kubernetes-rbac/api"
	"github.com/kismatic/kubernetes-rbac/repository"
)

type policy struct {
	Roles        []api.Role
	RoleBindings []api.RoleBinding
}

// FlatFileRepository implements the repository interface and
// persists objects on disk.
type FlatFileRepository struct {
	sync.RWMutex
	File string
}

// Create returns a new FlatFileRepository
func Create(file string) (repository.PolicyRepository, error) {

	// Ensure file exists
	if _, err := os.Stat(file); os.IsNotExist(err) {
		createEmptyRepo(file)
	}

	return &FlatFileRepository{
		File: file,
	}, nil
}

func createEmptyRepo(file string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(policy{})
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err != nil {
		return err
	}
	return nil
}

func (fr *FlatFileRepository) readPolicy() (*policy, error) {
	data, err := ioutil.ReadFile(fr.File)
	if err != nil {
		return nil, fmt.Errorf("Error reading the role repo file: %v", err)
	}

	p := &policy{}
	if err = json.Unmarshal(data, p); err != nil {
		return nil, fmt.Errorf("Error unmarshalling data from the role repo: %v", err)
	}
	return p, nil
}

func (fr *FlatFileRepository) writePolicy(p *policy) error {
	b, err := json.MarshalIndent(p, "", "    ")
	if err != nil {
		return err
	}
	if err = ioutil.WriteFile(fr.File, b, 0644); err != nil {
		return err
	}
	return nil
}
