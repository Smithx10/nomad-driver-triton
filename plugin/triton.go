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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Smithx10/nomad-driver-triton/client"
	"github.com/Smithx10/nomad-driver-triton/types"
	docker "github.com/fsouza/go-dockerclient"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/plugins/drivers"
	triton "github.com/joyent/triton-go"
	"github.com/joyent/triton-go/authentication"
	"github.com/joyent/triton-go/compute"
	"github.com/joyent/triton-go/network"
)

type TritonTaskHandler struct {
	client  *client.Client
	dclient *docker.Client
	logger  hclog.Logger
	fwLock  sync.RWMutex
}

type TritonTask struct {
	APIType      string
	Instance     *compute.Instance
	Ctx          context.Context
	Shutdown     context.CancelFunc
	StatusLock   sync.RWMutex
	CreateLock   sync.RWMutex
	Status       drivers.TaskState
	FWRules      []*network.FirewallRule
	ExitStrategy string
}

func (tth *TritonTaskHandler) NewTritonTask(dtc *drivers.TaskConfig, tc types.TaskConfig) (*TritonTask, error) {
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

	tth.logger.Info("W00T_IP", i.PrimaryIP)

	tt := &TritonTask{
		APIType:      tc.APIType,
		Instance:     i,
		Ctx:          sctx,
		Shutdown:     cancel,
		FWRules:      firewallRules,
		ExitStrategy: tc.ExitStrategy,
	}

	return tt, nil
}

func (tth *TritonTaskHandler) CreateFWRules(ctx context.Context, dtc *drivers.TaskConfig, tc types.TaskConfig) ([]*network.FirewallRule, error) {
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
			tth.logger.Warn("Error While Provisioning FWRules. Cleanup Initiated")
			// Clean Up already Created rules
			tth.DeleteFWRules(&TritonTask{
				Ctx:     ctx,
				FWRules: fwrules,
			})
			return nil, err
		}
		fwrules = append(fwrules, r)
	}

	tth.fwLock.Unlock()

	return fwrules, nil
}

func (tth *TritonTaskHandler) CreateInstance(ctx context.Context, dtc *drivers.TaskConfig, tc types.TaskConfig) (*compute.Instance, error) {
	tth.logger.Info("Inside tth CreateInstance")
	// TODO Assert Values
	if dtc.Resources == nil {
		// Guard against missing resources. We should never have been able to
		// schedule a job without specifying this.
		tth.logger.Error("task.Resources is empty")
		return nil, fmt.Errorf("task.Resources is empty")
	}

	// Init the CloudAPI Client and Create the instance with the inputs from the "tc" TaskConfig
	var instanceID string
	var instance *compute.Instance
	c, err := tth.client.Compute()
	if err != nil {
		return nil, err
	}

	// Handle Restart Policy For Docker
	var restartPolicy docker.RestartPolicy
	switch tc.Docker.RestartPolicy {
	case "Always":
		restartPolicy = docker.AlwaysRestart()
	case "OnFailure":
		restartPolicy = docker.RestartOnFailure(100)
	case "Never":
		restartPolicy = docker.NeverRestart()
	}

	// Handle Environment Variables and Metadata
	metadata := make(map[string]string)
	//cloudapi
	envvars := make(map[string]string)
	//docker
	labels := make(map[string]string)
	var dockerEnv []string

	for k, v := range dtc.Env {
		switch k {
		case "NOMAD_META_MY_KEY":
			metadata[k] = v
		case "NOMAD_META_my_key":
			metadata[k] = v
		default:
			envvars[k] = v
			dockerEnv = append(dockerEnv, fmt.Sprintf("%s=%s", k, v))
		}
	}

	// Public Network Setting
	if tc.Docker.PublicNetwork != "" {
		labels["triton.network.public"] = tc.Docker.PublicNetwork
	}

	// Docker Labels
	for k, v := range tc.Docker.Labels {
		labels[k] = v
	}

	// Add Affinity Rule to DockerEnv,  Currently the user is responsibile for supplying the affinity: prefix
	dockerEnv = append(dockerEnv, tc.Affinity...)

	envVars, _ := json.Marshal(envvars)

	metadata["env-vars"] = string(envVars)
	if tc.Cloud.UserData != "" {
		metadata["user-data"] = tc.Cloud.UserData
	}
	if tc.Cloud.UserScript != "" {
		metadata["user-script"] = tc.Cloud.UserScript
	}
	if tc.Cloud.CloudConfig != "" {
		metadata["cloud-config"] = tc.Cloud.CloudConfig
	}

	// Handle CNS
	if len(tc.CNS) > 0 {
		tc.Tags["triton.cns.services"] = fmt.Sprintf(strings.Join(tc.CNS, ","))
		labels["triton.cns.services"] = fmt.Sprintf(strings.Join(tc.CNS, ","))
	}

	// Resources
	tth.logger.Info(fmt.Sprintf("DEVENV: %s", dtc.Resources))

	// Make Name Reflect the Nomad Spec
	uniqueName := fmt.Sprintf("%s-%s-%s-%s", dtc.JobName, dtc.TaskGroupName, dtc.Name, dtc.AllocID[:8])

	// Package
	pkg, err := tth.GetPackage(tc.Package)
	if err != nil {
		return nil, err
	}
	labels["com.joyent.package"] = pkg.ID

	// PortMapping
	portBindings := make(map[docker.Port][]docker.PortBinding)

	if len(tc.Docker.Ports.TCP) > 0 {
		for _, v := range tc.Docker.Ports.TCP {
			port := docker.Port(fmt.Sprintf("%d/tcp", v))
			portBindings[port] = []docker.PortBinding{
				docker.PortBinding{
					HostIP:   "0.0.0.0",
					HostPort: fmt.Sprintf("%d", v),
				},
			}
		}
	}
	if len(tc.Docker.Ports.UDP) > 0 {
		for _, v := range tc.Docker.Ports.UDP {
			port := docker.Port(fmt.Sprintf("%d/udp", v))
			portBindings[port] = []docker.PortBinding{
				docker.PortBinding{
					HostIP:   "0.0.0.0",
					HostPort: fmt.Sprintf("%d", v),
				},
			}
		}
	}

	// Create the Instance
	if tc.APIType == "docker_api" {
		tth.logger.Info("Inside tth docker_api")

		// Handle Missing Tag
		if tc.Docker.Image.Tag == "" {
			tc.Docker.Image.Tag = "latest"
		}

		// See if AutoPull is set
		if tc.Docker.Image.AutoPull == true {
			err := tth.dclient.PullImage(
				docker.PullImageOptions{
					Repository: tc.Docker.Image.Name,
					Tag:        tc.Docker.Image.Tag,
					Context:    ctx,
				},
				docker.AuthConfiguration{},
			)
			if err != nil {
				return nil, err
			}
		}

		image := fmt.Sprintf("%s:%s", tc.Docker.Image.Name, tc.Docker.Image.Tag)

		// Create Docker Instance
		i, err := tth.dclient.CreateContainer(docker.CreateContainerOptions{
			Name: uniqueName,
			Config: &docker.Config{
				Cmd:        tc.Docker.Cmd,
				Entrypoint: tc.Docker.Entrypoint,
				Env:        dockerEnv,
				Image:      image,
				Labels:     labels,
				OpenStdin:  tc.Docker.OpenStdin,
				StdinOnce:  tc.Docker.StdInOnce,
				Tty:        tc.Docker.TTY,
				WorkingDir: tc.Docker.WorkingDir,
				Hostname:   tc.Docker.Hostname,
				Domainname: tc.Docker.Domainname,
				User:       tc.Docker.User,
			},
			HostConfig: &docker.HostConfig{
				NetworkMode:     tc.Docker.PrivateNetwork,
				RestartPolicy:   restartPolicy,
				PortBindings:    portBindings,
				PublishAllPorts: tc.Docker.Ports.PublishAll,
				DNS:             tc.Docker.DNS,
				DNSSearch:       tc.Docker.DNSSearch,
				ExtraHosts:      tc.Docker.ExtraHosts,
				LogConfig:       docker.LogConfig(tc.Docker.LogConfig),
			},
			Context: ctx,
		})
		if err != nil {
			return nil, err
		}
		// OverRide Get INstance with Docker Instance ID
		instanceID = fmt.Sprintf("%s-%s-%s-%s-%s", i.ID[0:8], i.ID[8:12], i.ID[12:16], i.ID[16:20], i.ID[20:32])

		err = c.Instances().AddTags(ctx, &compute.AddTagsInput{
			ID:   instanceID,
			Tags: tc.Tags,
		})
		if err != nil {
			tth.logger.Info(fmt.Sprintln(err))
		}

		_, err = c.Instances().UpdateMetadata(ctx, &compute.UpdateMetadataInput{
			ID:       instanceID,
			Metadata: metadata,
		})
		if err != nil {
			tth.logger.Info(fmt.Sprintln(err))
		}

		tth.dclient.StartContainer(i.ID, i.HostConfig)
	}
	if tc.APIType == "cloud_api" {
		// Networks
		networks, err := tth.GetNetworks(tc.Cloud.Networks)
		if err != nil {
			return nil, err
		}

		// Image
		image, err := tth.GetImage(tc.Cloud.Image)
		if err != nil {
			return nil, err
		}

		tth.logger.Info("Inside tth cloud_api")
		i, err := c.Instances().Create(ctx, &compute.CreateInstanceInput{
			Name:            uniqueName,
			Image:           image,
			Package:         pkg.ID,
			Networks:        networks,
			Tags:            tc.Tags,
			Metadata:        metadata,
			Affinity:        tc.Affinity,
			FirewallEnabled: tc.FWEnabled,
		})
		if err != nil {
			return nil, err
		}
		instanceID = i.ID
		instance = i
	}

	// Block Until The Machine is Running
	for {
		// pi (Provisioned Instance)
		pi, _ := c.Instances().Get(ctx, &compute.GetInstanceInput{ID: instanceID})

		if pi.State == "failed" {
			return nil, errors.New("Provisioning failed")
		}

		if pi.State == "running" && pi.PrimaryIP != "" {
			tth.logger.Info("W00T_PRIMARYIP", pi.PrimaryIP)
			instance = pi
			break
		}

		time.Sleep(5 * time.Second)
	}

	// Enable Deletion Protection if true
	if tc.DeletionProtection == true {
		err := c.Instances().EnableDeletionProtection(ctx, &compute.EnableDeletionProtectionInput{
			InstanceID: instanceID,
		})
		if err != nil {
			return nil, errors.New("Applying Deletion-Protection")
		}
	}

	return instance, nil
}

func (tth *TritonTaskHandler) DestroyTritonTask(h *taskHandle, force bool) error {
	tth.logger.Info("Inside tth DestroyTritonTask")
	// Attempt To Bring it Down Softly if Force isn't true
	if h.IsRunning() && force != true {
		err := h.tth.ShutdownInstance(h.tritonTask)
		if err != nil {
			return err
		}
	}

	// Delete the instance,  Note if we are using the deleted exit strategy we will never land in destroy task unless the instance has deleted.  So we shouldn't attempt to delete twice.
	if h.tritonTask.ExitStrategy == "stopped" {
		err := h.tth.DeleteInstance(h.tritonTask)
		if err != nil {
			return err
		}
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
	if err := c.Instances().Stop(tt.Ctx, &compute.StopInstanceInput{InstanceID: tt.Instance.ID}); err != nil {
		return err
	}

	// Block Until The Machine is Stopped
	for {
		pi, err := c.Instances().Get(tt.Ctx, &compute.GetInstanceInput{ID: tt.Instance.ID})
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
	if tt.ExitStrategy == "deleted" {
		err := tth.DeleteInstance(tt)
		if err != nil {
			return err
		}
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

	// If Docker, Append Docker Rules that need to be cleaned up
	if tt.APIType == "docker_api" {
		rules, _ := n.Firewall().ListMachineRules(tt.Ctx, &network.ListMachineRulesInput{
			MachineID: tt.Instance.ID,
		})

		//Append Rules
		tt.FWRules = append(tt.FWRules, rules...)
	}
	// Iterate over the rules and delete them if the proper conditions are met
	for _, v := range tt.FWRules {
		tth.logger.Info(fmt.Sprintf("Inside TTFWRULES: %s", v.ID))

		// We can encounter a shutdown race, so we will wait for members to be 0 for 3 iterations and move on.  We do this because we don't want to delete a firewall rule that a machine is depending on.  This machine could have been provisioned. We will Warn in the log of this condition, and perhaps inform the user.  TODO find out how to do that. LOL.
		go func(fwr *network.FirewallRule) {
			timeout := 1
			for {
				// Because Rules can be used by many instances with multiple tags only Delete the Rule if we are the last instance using it.  This requires that the length of Members is 0
				members, _ := n.Firewall().ListRuleMachines(tt.Ctx, &network.ListRuleMachinesInput{
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
					n.Firewall().DeleteRule(tt.Ctx, &network.DeleteRuleInput{
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
	if err := c.Instances().Delete(tt.Ctx, &compute.DeleteInstanceInput{ID: tt.Instance.ID}); err != nil {
		return err
	}

	// Block Until The Machine is Deleted
	for {
		_, err := c.Instances().Get(tt.Ctx, &compute.GetInstanceInput{ID: tt.Instance.ID})
		if err != nil {
			break
		}
		time.Sleep(4 * time.Second)
	}

	return nil
}

//func (tth *TritonTaskHandler) CleanUpTritonTask(ctx context., dtc *drivers.TaskConfig, tc TaskConfig) error {
//tth.logger.Info("Inside tth CleanUpTritonTask")
//// Cleanup If the Task Allocation failed

//return nil
//}

func (tth *TritonTaskHandler) GetInstStatus(tt *TritonTask) {
	tth.logger.Info("Inside GetInstStatus")
	for {
		select {
		case <-tt.Ctx.Done():
			return
		default:
			c, err := tth.client.Compute()
			if err != nil {
				return
			}
			i, err := c.Instances().Get(tt.Ctx, &compute.GetInstanceInput{ID: tt.Instance.ID})
			if err != nil {
				tth.logger.Warn(fmt.Sprintf("GET_STATUS_FAILED: %s", err))
			}

			tt.StatusLock.Lock()
			tth.logger.Info(fmt.Sprintf("STATUS: %s", i.State))
			//tth.logger.Info(fmt.Sprintf("FWRULES: %s", tt.FWRules))

			switch i.State {
			case "running":
				tt.Status = drivers.TaskStateRunning
			case "failed":
				tt.Status = drivers.TaskStateExited
				return
			case tt.ExitStrategy:
				tt.Status = drivers.TaskStateExited
				return
			default:
				tt.Status = drivers.TaskStateUnknown
			}
			tt.StatusLock.Unlock()

			// Poll time for Instance State
			time.Sleep(5 * time.Second)
		}
	}
}

func NewTritonTaskHandler(logger hclog.Logger) *TritonTaskHandler {
	// Init the Triton Client
	keyID := triton.GetEnv("KEY_ID")
	accountName := triton.GetEnv("ACCOUNT")
	keyMaterial := triton.GetEnv("KEY_MATERIAL")
	userName := triton.GetEnv("USER")
	insecure := false
	if triton.GetEnv("INSECURE") != "" {
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
		TritonURL:   triton.GetEnv("URL"),
		AccountName: accountName,
		Username:    userName,
		Signers:     []authentication.Signer{signer},
	}

	// Triton Docker Config
	dockerClient, err := docker.NewClientFromEnv()

	return &TritonTaskHandler{
		client: &client.Client{
			Config:                tritonConfig,
			InsecureSkipTLSVerify: insecure,
			AffinityLock:          &sync.RWMutex{},
		},
		dclient: dockerClient,
		logger:  logger,
	}
}

func (tth *TritonTaskHandler) GetImage(i types.CloudImage) (string, error) {
	tth.logger.Info("Inside tth getImage")

	c, err := tth.client.Compute()
	if err != nil {
		return "", err
	}

	input := &compute.ListImagesInput{}

	if i.UUID != "" {
		return i.UUID, nil
	} else {
		if i.Name != "" {
			input.Name = i.Name
		}

		if i.Version != "" {
			input.Version = i.Version
		}

	}

	images, err := c.Images().List(context.Background(), input)
	if err != nil {
		return "", err
	}

	var image *compute.Image
	if len(images) == 0 {
		return "", fmt.Errorf("Your image query returned no results. Please change " +
			"your search criteria and try again.")
	}

	if len(images) > 1 {
		recent := i.MostRecent
		log.Printf("[DEBUG] triton_image - multiple results found and `most_recent` is set to: %t", recent)
		if recent {
			image = mostRecentImages(images)
		} else {
			return "", fmt.Errorf("Your image query returned more than one result. " +
				"Please try a more specific image search criteria.")
		}
	} else {
		image = images[0]
	}

	return image.ID, nil
}

func mostRecentImages(images []*compute.Image) *compute.Image {
	return sortImages(images)[0]
}

type imageSort []*compute.Image

func sortImages(images []*compute.Image) []*compute.Image {
	sortedImages := images
	sort.Sort(sort.Reverse(imageSort(sortedImages)))
	return sortedImages
}

func (a imageSort) Len() int {
	return len(a)
}

func (a imageSort) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a imageSort) Less(i, j int) bool {
	itime := a[i].PublishedAt
	jtime := a[j].PublishedAt
	re := regexp.MustCompile("[0-9]+")
	iversion := strings.Join(re.FindAllString(a[i].Version, -1), "")
	jversion := strings.Join(re.FindAllString(a[j].Version, -1), "")
	if iversion == jversion {
		return itime.Unix() < jtime.Unix()
	} else {
		return itime.Unix() < jtime.Unix() && iversion < jversion
	}
}

func (tth *TritonTaskHandler) GetNetworks(ns []types.Network) ([]string, error) {
	tth.logger.Info("Inside tth GetNetworks")

	n, err := tth.client.Network()
	if err != nil {
		return nil, err
	}

	//tth.logger.Info(fmt.Sprintln("NETWORKS: ", ns))

	// UUID Provided
	var networks []string
	for _, v := range ns {
		if v.UUID != "" {
			networks = append(networks, v.UUID)
		}
	}
	if len(networks) > 0 {
		return networks, nil
	}

	// Names provided
	networkList, err := n.List(context.Background(), &network.ListInput{})
	if err != nil {
		return nil, err
	}
	for _, net := range ns {
		//tth.logger.Info(fmt.Sprintln("NET: ", net))
		for _, nw := range networkList {
			//tth.logger.Info(fmt.Sprintln("NW: ", nw))
			if net.Name == nw.Name {
				networks = append(networks, nw.Id)
			}
		}
	}
	//tth.logger.Info(fmt.Sprintln("NETWORKS: ", networks))
	if len(networks) > 0 {
		return networks, nil
	}

	return nil, fmt.Errorf("Networks Provided Not Found")
}

func (tth *TritonTaskHandler) GetPackage(p types.Package) (*compute.Package, error) {
	tth.logger.Info("Inside tth GetPackage")

	c, err := tth.client.Compute()
	if err != nil {
		return nil, err
	}

	input := &compute.ListPackagesInput{}

	if p.UUID != "" {
		return &compute.Package{ID: p.UUID}, nil
	} else {
		if p.Name != "" {
			input.Name = p.Name
		}

		if p.Version != "" {
			input.Version = p.Version
		}
	}

	pkg, err := c.Packages().List(context.Background(), input)
	if err != nil {
		return nil, err
	}

	if len(pkg) > 1 {
		return nil, fmt.Errorf("More than 1 Package found, Please be more specific in your search criteria")
	}
	if len(pkg) == 0 {
		return nil, fmt.Errorf("No Package found, Please be more specific in your search criteria")
	}

	return pkg[0], nil
}
