package plugin

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"git.bdf-cloud.iqvia.net/bdf-cloud/bdf-cloud/client"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/plugins/drivers"
	triton "github.com/joyent/triton-go"
	"github.com/joyent/triton-go/authentication"
	"github.com/joyent/triton-go/compute"
	"github.com/joyent/triton-go/network"
)

type TritonTaskHandler struct {
	client *client.Client
	logger hclog.Logger
	fwLock sync.RWMutex
}

type TritonTask struct {
	instance   *compute.Instance
	ctx        context.Context
	shutdown   context.CancelFunc
	statusLock sync.RWMutex
	createLock sync.RWMutex
	status     drivers.TaskState
	fwrules    []*network.FirewallRule
}

func (tth *TritonTaskHandler) NewTritonTask(dtc *drivers.TaskConfig, tc TaskConfig) (*TritonTask, error) {
	// Initialize the Contexts for the long running TritonTask Supervisor.  The role of these contexts is to be able to cancel out all polling of the state of a Instance on Triton.
	tth.logger.Info("Inside tth NewTritonTask")
	ctx := context.Background()
	sctx, cancel := context.WithCancel(ctx)

	// Create FWRules
	var firewallRules []*network.FirewallRule
	if tc.FWEnabled && len(tc.FWRules) > 0 {
		fwrs, err := tth.CreateFWRules(sctx, dtc, tc)
		if err != nil {
			return nil, err
		}
		firewallRules = fwrs
	}

	// Create an instance
	i, err := tth.CreateInstance(sctx, dtc, tc)
	if err != nil {
		return nil, err
	}

	tt := &TritonTask{
		instance: i,
		ctx:      sctx,
		shutdown: cancel,
		fwrules:  firewallRules,
	}

	return tt, nil
}

func (tth *TritonTaskHandler) CreateFWRules(ctx context.Context, dtc *drivers.TaskConfig, tc TaskConfig) ([]*network.FirewallRule, error) {
	tth.fwLock.Lock()
	tth.logger.Info("Inside tth CreateFWRules")

	n, err := tth.client.Network()
	if err != nil {
		return nil, err
	}

	var fwrules []*network.FirewallRule

	rules, err := n.Firewall().ListRules(ctx, &network.ListRulesInput{})
	if err != nil {
		return nil, err
	}

	for k, v := range tc.FWRules {
		for _, rule := range rules {
			cleanRule := strings.ReplaceAll(rule.Rule, "\"", "")
			if cleanRule == v {
				delete(tc.FWRules, k)
				fwrules = append(fwrules, rule)
			}
		}
	}

	for k, v := range tc.FWRules {
		r, err := n.Firewall().CreateRule(ctx, &network.CreateRuleInput{
			Rule:        v,
			Enabled:     true,
			Description: fmt.Sprintf("Nomad FWRule for service: %s", k),
		})
		if err != nil {
			return nil, err
		}
		fwrules = append(fwrules, r)

	}

	tth.fwLock.Unlock()

	return fwrules, nil
}

func (tth *TritonTaskHandler) CreateInstance(ctx context.Context, dtc *drivers.TaskConfig, tc TaskConfig) (*compute.Instance, error) {
	tth.logger.Info("Inside tth CreateInstance")
	// TODO Assert Values
	if dtc.Resources == nil {
		// Guard against missing resources. We should never have been able to
		// schedule a job without specifying this.
		tth.logger.Error("task.Resources is empty")
		return nil, fmt.Errorf("task.Resources is empty")
	}

	// Init the CloudAPI Client and Create the instance with the inputs from the "tc" TaskConfig
	c, err := tth.client.Compute()
	if err != nil {
		return nil, err
	}

	// Handle Environment Variables and Metadata
	metadata := make(map[string]string)
	envvars := make(map[string]string)

	for k, v := range dtc.Env {

		switch k {
		case "NOMAD_META_MY_KEY":
			metadata[k] = v
		case "NOMAD_META_my_key":
			metadata[k] = v
		default:
			envvars[k] = v
		}
	}

	envVars, _ := json.Marshal(envvars)

	metadata["env-vars"] = string(envVars)
	if tc.UserData != "" {
		metadata["user-data"] = tc.UserData
	}
	if tc.UserScript != "" {
		metadata["user-script"] = tc.UserScript
	}
	if tc.CloudConfig != "" {
		metadata["cloud-config"] = tc.CloudConfig
	}

	// Handle CNS
	if len(tc.CNS) > 0 {
		tc.Tags["triton.cns.services"] = fmt.Sprintf(strings.Join(tc.CNS, ","))
	}

	// Networks
	//var networks []string

	// Resources
	tth.logger.Info(fmt.Sprintf("DEVENV: %s", dtc.Resources))

	// Make Name Reflect the Nomad Spec
	uniqueName := fmt.Sprintf("%s-%s-%s-%s", dtc.JobName, dtc.TaskGroupName, dtc.Name, dtc.AllocID[:8])

	// Create the Instance
	i, err := c.Instances().Create(ctx, &compute.CreateInstanceInput{
		Name:            uniqueName,
		Image:           tc.Image,
		Package:         tc.Package,
		Networks:        tc.Networks,
		Tags:            tc.Tags,
		Metadata:        metadata,
		FirewallEnabled: tc.FWEnabled,
	})
	if err != nil {
		return nil, err
	}

	// Block Until The Machine is Running
	for {
		// pi (Provisioned Instance)
		pi, err := c.Instances().Get(ctx, &compute.GetInstanceInput{ID: i.ID})
		if err != nil {
			return nil, err
		}

		if pi.State == "failed" {
			return nil, errors.New("Provisioning failed")
		}

		if pi.State == "running" && pi.PrimaryIP != "" {
			return pi, nil
		}

		time.Sleep(5 * time.Second)
	}

	return i, nil
}

func (tth *TritonTaskHandler) DestroyTritonTask(h *taskHandle, force bool) error {
	tth.logger.Info("Inside tth DestroyTritonTask")
	// Attempt To Bring it Down Softly if Force isn't true
	if force != true {
		err := h.tth.ShutdownInstance(h.tritonTask)
		if err != nil {
			return err
		}
	}

	// Delete the instance
	err := h.tth.DeleteInstance(h.tritonTask)
	if err != nil {
		return err
	}

	// Delete FWRules
	go h.tth.DeleteFWRules(h.tritonTask)

	return nil
}

// Shutdown The Instance Gracefully (Not -Force)
func (tth *TritonTaskHandler) ShutdownInstance(tt *TritonTask) error {
	// TODO Assert Values
	tth.logger.Info("Inside tth ShutdownInstance")

	// Init the CloudAPI Client and Create the instance with the inputs from the "tc" TaskConfig
	c, err := tth.client.Compute()
	if err != nil {
		return err
	}

	// Stop the Instance
	if err := c.Instances().Stop(tt.ctx, &compute.StopInstanceInput{InstanceID: tt.instance.ID}); err != nil {
		return err
	}

	// Block Until The Machine is Stopped
	for {
		pi, err := c.Instances().Get(tt.ctx, &compute.GetInstanceInput{ID: tt.instance.ID})
		if err != nil {
			return err
		}

		if pi.State == "failed" {
			return errors.New("Shutdown failed")
		}

		if pi.State == "stopped" {
			break
		}

		time.Sleep(5 * time.Second)
	}

	return nil
}

func (tth *TritonTaskHandler) DeleteFWRules(tt *TritonTask) error {
	// TODO Assert Values
	tth.logger.Info("Inside tth DeleteFWRules")

	// Init the CloudAPI Client and Create the instance with the inputs from the "tc" TaskConfig
	n, err := tth.client.Network()
	if err != nil {
		return err
	}

	// Iterate over the rules and delete them if the proper conditions are met
	for _, v := range tt.fwrules {
		tth.logger.Info(fmt.Sprintf("Inside TTFWRULES: %s", v.ID))

		// We can encounter a shutdown race, so we will wait for members to be 0 for 3 iterations and move on.  We do this because we don't want to delete a firewall rule that a machine is depending on.  This machine could have been provisioned. We will Warn in the log of this condition, and perhaps inform the user.  TODO find out how to do that. LOL.

		go func(fwr *network.FirewallRule) {
			timeout := 1
			for {
				// Because Rules can be used by many instances with multiple tags only Delete the Rule if we are the last instance using it.  This requires that the length of Members is 0
				members, _ := n.Firewall().ListRuleMachines(tt.ctx, &network.ListRuleMachinesInput{
					ID: fwr.ID,
				})

				if len(members) != 0 {
					if timeout > 10 {
						break
					}
					time.Sleep(6 * time.Second)
					timeout++
				}

				if len(members) == 0 {
					n.Firewall().DeleteRule(tt.ctx, &network.DeleteRuleInput{
						ID: fwr.ID,
					})
					tth.logger.Info(fmt.Sprintf("FW Rule Deleted: %s", fwr.ID))
					break
				}
			}
		}(v)
	}

	return nil
}

func (tth *TritonTaskHandler) DeleteInstance(tt *TritonTask) error {
	// TODO Assert Values
	tth.logger.Info("Inside tth Delete instance")

	// Init the CloudAPI Client and Create the instance with the inputs from the "tc" TaskConfig
	c, err := tth.client.Compute()
	if err != nil {
		return err
	}

	// Delete the Instance
	if err := c.Instances().Delete(tt.ctx, &compute.DeleteInstanceInput{ID: tt.instance.ID}); err != nil {
		return err
	}

	// Block Until The Machine is Deleted
	for {
		_, err := c.Instances().Get(tt.ctx, &compute.GetInstanceInput{ID: tt.instance.ID})
		if err != nil {
			break
		}
		time.Sleep(2 * time.Second)
	}

	return nil
}

func (tth *TritonTaskHandler) CleanUpTritonTask(tt *TritonTask) error {
	tth.logger.Info("Inside tth CleanUpTritonTask")
	// Cleanup the Actul Instance if it was created.
	if err := tth.DeleteInstance(tt); err != nil {
		return err
	}

	if err := tth.DeleteInstance(tt); err != nil {
		return err
	}

	if len(tt.fwrules) > 0 {
		if err := tth.DeleteFWRules(tt); err != nil {
			return err
		}
	}

	return nil
}

func (tth *TritonTaskHandler) GetInstStatus(tt *TritonTask) {
	tth.logger.Info("Inside GetInstStatus")
	for {
		select {
		case <-tt.ctx.Done():
			return
		default:
			c, err := tth.client.Compute()
			if err != nil {
				return
			}
			i, err := c.Instances().Get(tt.ctx, &compute.GetInstanceInput{ID: tt.instance.ID})
			if err != nil {
				return
			}

			tt.statusLock.Lock()
			tth.logger.Info(fmt.Sprintf(i.State))
			tth.logger.Info(fmt.Sprintln(tt.fwrules))

			switch i.State {
			case "running":
				tt.status = drivers.TaskStateRunning
			case "failed":
				tt.status = drivers.TaskStateExited
				return
			case "stopped":
				tt.status = drivers.TaskStateExited
				return
			default:
				tt.status = drivers.TaskStateUnknown
			}
			tt.statusLock.Unlock()

			// Poll time for Instance State
			time.Sleep(5 * time.Second)
		}
	}

}

func NewTritonTaskHandler(logger hclog.Logger) *TritonTaskHandler {
	// Init the Triton Client
	keyID := os.Getenv("SDC_KEY_ID")
	accountName := os.Getenv("SDC_ACCOUNT")
	keyMaterial := os.Getenv("SDC_KEY_MATERIAL")
	userName := os.Getenv("SDC_USER")
	insecure := false
	if os.Getenv("SDC_INSECURE") != "" {
		insecure = true
	}

	var signer authentication.Signer
	var err error

	if keyMaterial == "" {
		input := authentication.SSHAgentSignerInput{
			KeyID:       keyID,
			AccountName: accountName,
			Username:    userName,
		}
		signer, err = authentication.NewSSHAgentSigner(input)
		if err != nil {
			log.Fatalf("Error Creating SSH Agent Signer: {{err}}", err)
		}
	} else {
		var keyBytes []byte
		if _, err = os.Stat(keyMaterial); err == nil {
			keyBytes, err = ioutil.ReadFile(keyMaterial)
			if err != nil {
				log.Fatalf("Error reading key material from %s: %s",
					keyMaterial, err)
			}
			block, _ := pem.Decode(keyBytes)
			if block == nil {
				log.Fatalf(
					"Failed to read key material '%s': no key found", keyMaterial)
			}

			if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
				log.Fatalf(
					"Failed to read key '%s': password protected keys are\n"+
						"not currently supported. Please decrypt the key prior to use.", keyMaterial)
			}

		} else {
			keyBytes = []byte(keyMaterial)
		}

		input := authentication.PrivateKeySignerInput{
			KeyID:              keyID,
			PrivateKeyMaterial: keyBytes,
			AccountName:        accountName,
			Username:           userName,
		}
		signer, err = authentication.NewPrivateKeySigner(input)
		if err != nil {
			log.Fatalf("Error Creating SSH Private Key Signer: {{err}}", err)
		}
	}

	// Triton Client Config
	tritonConfig := &triton.ClientConfig{
		TritonURL:   os.Getenv("SDC_URL"),
		AccountName: accountName,
		Username:    userName,
		Signers:     []authentication.Signer{signer},
	}

	return &TritonTaskHandler{
		client: &client.Client{
			Config:                tritonConfig,
			InsecureSkipTLSVerify: insecure,
			AffinityLock:          &sync.RWMutex{},
		},
		logger: logger,
	}
}
