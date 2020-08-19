package plugin

import (
	"github.com/Smithx10/nomad-driver-triton/types"
	docker "github.com/fsouza/go-dockerclient"
)

// firstValidAuth tries a list of auth backends, returning first error or AuthConfiguration
func firstValidAuth(repo string, backends []authBackend) (*docker.AuthConfiguration, error) {
	for _, backend := range backends {
		auth, err := backend(repo)
		if auth != nil || err != nil {
			return auth, err
		}
	}
	return nil, nil
}

// authFromTaskConfig generates an authBackend for any auth given in the task-configuration
func authFromTaskConfig(tc types.TaskConfig) authBackend {
	return func(string) (*docker.AuthConfiguration, error) {
		// If all auth fields are empty, return
		if len(tc.Docker.Auth.Username) == 0 && len(tc.Docker.Auth.Password) == 0 && len(tc.Docker.Auth.Email) == 0 && len(tc.Docker.Auth.ServerAddr) == 0 {
			return nil, nil
		}
		return &docker.AuthConfiguration{
			Username:      tc.Docker.Auth.Username,
			Password:      tc.Docker.Auth.Password,
			Email:         tc.Docker.Auth.Email,
			ServerAddress: tc.Docker.Auth.ServerAddr,
		}, nil
	}
}

// authIsEmpty returns if auth is nil or an empty structure
func authIsEmpty(auth *docker.AuthConfiguration) bool {
	if auth == nil {
		return false
	}
	return auth.Username == "" &&
		auth.Password == "" &&
		auth.Email == "" &&
		auth.ServerAddress == ""
}
