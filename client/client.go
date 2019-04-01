package client

import (
	"sync"

	"github.com/hashicorp/errwrap"

	triton "github.com/joyent/triton-go"
	"github.com/joyent/triton-go/account"
	"github.com/joyent/triton-go/compute"
	"github.com/joyent/triton-go/identity"
	"github.com/joyent/triton-go/network"
	"github.com/joyent/triton-go/services"
)

// Client represents all internally accessible Triton APIs utilized by this
// provider and the configuration necessary to connect to them.
type Client struct {
	Config                *triton.ClientConfig
	InsecureSkipTLSVerify bool
	AffinityLock          *sync.RWMutex
}

func (c Client) Account() (*account.AccountClient, error) {
	accountClient, err := account.NewClient(c.Config)
	if err != nil {
		return nil, errwrap.Wrapf("Error Creating Triton Account Client: {{err}}", err)
	}

	if c.InsecureSkipTLSVerify {
		accountClient.Client.InsecureSkipTLSVerify()
	}
	return accountClient, nil
}

func (c Client) Compute() (*compute.ComputeClient, error) {
	computeClient, err := compute.NewClient(c.Config)
	if err != nil {
		return nil, errwrap.Wrapf("Error Creating Triton Compute Client: {{err}}", err)
	}
	if c.InsecureSkipTLSVerify {
		computeClient.Client.InsecureSkipTLSVerify()
	}
	return computeClient, nil
}

func (c Client) Identity() (*identity.IdentityClient, error) {
	identityClient, err := identity.NewClient(c.Config)
	if err != nil {
		return nil, errwrap.Wrapf("Error Creating Triton Identity Client: {{err}}", err)
	}
	if c.InsecureSkipTLSVerify {
		identityClient.Client.InsecureSkipTLSVerify()
	}
	return identityClient, nil
}

func (c Client) Network() (*network.NetworkClient, error) {
	networkClient, err := network.NewClient(c.Config)
	if err != nil {
		return nil, errwrap.Wrapf("Error Creating Triton Network Client: {{err}}", err)
	}
	if c.InsecureSkipTLSVerify {
		networkClient.Client.InsecureSkipTLSVerify()
	}
	return networkClient, nil
}

func (c Client) Services() (*services.ServiceGroupClient, error) {
	servicesClient, err := services.NewClient(c.Config)
	if err != nil {
		return nil, errwrap.Wrapf("Error Creating Triton Services Client: {{err}}", err)
	}
	if c.InsecureSkipTLSVerify {
		servicesClient.Client.InsecureSkipTLSVerify()
	}
	return servicesClient, nil
}
