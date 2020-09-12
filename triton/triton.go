package triton

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Smithx10/nomad-driver-triton/client"
	docker "github.com/fsouza/go-dockerclient"
	"github.com/gofrs/uuid"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/plugins/drivers"
	"github.com/joyent/triton-go/compute"
	"github.com/joyent/triton-go/network"
)

// tritonClientInterface encapsulates all the required AWS functionality to
// successfully run tasks via this plugin.
type tritonClientInterface interface {

	// DescribeCluster is used to determine the health of the plugin by
	// querying Triton and checking its current status
	DescribeCluster(ctx context.Context) error

	// DescribeTaskStatus attempts to return the current health status of the
	// Triton Instance and should be used for health checking.
	DescribeTaskStatus(ctx context.Context, instUUID string) (string, error)

	// RunTask is used to trigger the running of a new Triton instance based on the
	// provided configuration. The UUID of the Instance, as well as any errors are
	// returned to the caller.
	RunTask(ctx context.Context, dtc *drivers.TaskConfig, cfg TaskConfig) (string, error)

	// StopTask stops the running Triton Instance
	StopTask(ctx context.Context, instUUID string) error

	// DestroyTask stops the running Triton Instance
	DestroyTask(ctx context.Context, instUUID string) error
}

type tritonClient struct {
	tclient *client.Client
	dclient *docker.Client
	logger  hclog.Logger
}

type tritonInstanceInput struct {
	dockerInput       *docker.CreateContainerOptions
	dockerAuthConfig  *docker.AuthConfiguration
	dockerPullImgOpts *docker.PullImageOptions
	dockerMdata       map[string]string
	tritonInput       *compute.CreateInstanceInput
	apitype           string
}

// DescribeCluster satisfies the triton.tritonClientInterface DescribeCluster
// interface function.
func (c tritonClient) DescribeCluster(ctx context.Context) error {
	compute, err := c.tclient.Compute()
	if err != nil {
		return err
	}

	_, err = compute.Ping(ctx)
	if err != nil {
		return err
	}

	return nil
}

// DescribeTaskStatus satisfies the triton.tritonClientInterface DescribeTaskStatus
// interface function.
func (c tritonClient) DescribeTaskStatus(ctx context.Context, instUUID string) (string, error) {
	cmpt, err := c.tclient.Compute()
	if err != nil {
		return "", err
	}
	i, _ := cmpt.Instances().Get(ctx, &compute.GetInstanceInput{ID: instUUID})
	if i == nil {
		return tritonInstanceStatusUnknown, nil
	}

	return i.State, nil
}

// RunTask satisfies the triton.tritonClientInterface RunTask interface function.
func (c tritonClient) RunTask(ctx context.Context, dtc *drivers.TaskConfig, cfg TaskConfig) (string, error) {
	c.logger.Info("In_RunTask")

	// instanceID Is used for query a deployed instance for both dockerapi and cloudapi
	var instanceID string

	input, err := c.buildTaskInput(ctx, dtc, cfg)
	if err != nil {
		return "", err
	}

	// Init compute client to communicate to Triton
	cmpt, err := c.tclient.Compute()
	if err != nil {
		return "", err
	}

	if input.apitype == "cloudapi" {
		i, err := cmpt.Instances().Create(ctx, input.tritonInput)
		if err != nil {
			return "", err
		}

		err = c.waitForInstState(cmpt, i.ID, tritonInstanceStatusRunning, 60)
		if err != nil {
			return "", err
		}

		instanceID = i.ID
	}

	if input.apitype == "dockerapi" {
		// If AutoPull is enabled, pull the image.
		if cfg.Docker.Image.AutoPull == true {
			err := c.dclient.PullImage(
				*input.dockerPullImgOpts,
				*input.dockerAuthConfig,
			)
			if err != nil {
				return "", err
			}
		}

		// Create Docker Instance
		i, err := c.dclient.CreateContainer(*input.dockerInput)
		if err != nil {
			return "", err
		}
		// overRide get instance with docker instance id
		instanceID = fmt.Sprintf("%s-%s-%s-%s-%s", i.ID[0:8], i.ID[8:12], i.ID[12:16], i.ID[16:20], i.ID[20:32])

		// Create Container Blocks,  but lets poll anyway
		// wait for instance to be provisioned.  we land in the "stopped" state before being able to start
		err = c.waitForInstState(cmpt, instanceID, tritonInstanceStatusStopped, 60)
		if err != nil {
			return "", err
		}

		// Triton DockerAPI doesn't allow for Tag Placement, Update via CloudAPI
		if len(cfg.Tags) > 0 {
			err = cmpt.Instances().AddTags(ctx, &compute.AddTagsInput{
				ID:   instanceID,
				Tags: cfg.Tags,
			})
			if err != nil {
				return "", err
			}
		}

		if len(input.dockerMdata) > 0 {
			// Triton DockerAPI doesn't allow for Metadata Placement, Update via CloudAPI
			_, err = cmpt.Instances().UpdateMetadata(ctx, &compute.UpdateMetadataInput{
				ID:       instanceID,
				Metadata: input.dockerMdata,
			})
			if err != nil {
				return "", err
			}
		}

		// Start the Docker Container
		c.dclient.StartContainer(i.ID, i.HostConfig)
		err = c.waitForInstState(cmpt, instanceID, tritonInstanceStatusRunning, 5)
		if err != nil {
			return "", err
		}
	}

	// Enable Deletion Protection if true
	if cfg.DeletionProtection == true {
		err := cmpt.Instances().EnableDeletionProtection(ctx, &compute.EnableDeletionProtectionInput{
			InstanceID: instanceID,
		})
		if err != nil {
			return "", errors.New("Failed to Apply Deletion-Protection")
		}
	}

	return instanceID, nil
}

// buildTaskInput is used to convert the jobspec supplied configuration input
// into the appropriate triton.RunTaskInput object.
func (c tritonClient) buildTaskInput(ctx context.Context, dtc *drivers.TaskConfig, cfg TaskConfig) (*tritonInstanceInput, error) {
	c.logger.Info("building input for triton instance", "TaskConfig", hclog.Fmt("%+v", cfg))

	var input *tritonInstanceInput
	// An Instance must be for CloudAPI or DockerAPI.  Check to make sure both are not configured
	// in our hclConfig.  Images must be provided for both APIs so we can use that to compare
	if cfg.Cloud.Image.Name != "" && cfg.Docker.Image.Name != "" {
		return nil, fmt.Errorf("triton driver config can only deploy to either CloudAPI or Docker.")

	}

	// Build Inputs. No Instance Provisioning or Image Pulling takes place here.
	if cfg.Cloud.Image.Name != "" {
		i, err := c.buiuldCloudAPIInput(ctx, dtc, cfg)
		if err != nil {
			return nil, err
		}
		input = i
	}
	if cfg.Docker.Image.Name != "" {
		i, err := c.buildDockerAPIInput(ctx, dtc, cfg)
		if err != nil {
			return nil, err
		}
		input = i
	}

	// Be sure that we have an image and a package
	return input, nil
}

func (c tritonClient) buiuldCloudAPIInput(ctx context.Context, dtc *drivers.TaskConfig, cfg TaskConfig) (*tritonInstanceInput, error) {
	c.logger.Info("building input for CloudAPI")

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
	if cfg.Cloud.UserData != "" {
		metadata["user-data"] = cfg.Cloud.UserData
	}
	if cfg.Cloud.UserScript != "" {
		metadata["user-script"] = cfg.Cloud.UserScript
	}
	if cfg.Cloud.CloudConfig != "" {
		metadata["cloud-config"] = cfg.Cloud.CloudConfig
	}

	// Handle CNS
	if len(cfg.CNS) > 0 {
		cfg.Tags["triton.cns.services"] = fmt.Sprintf(strings.Join(cfg.CNS, ","))
	}

	// Make Name Reflect the Nomad Spec
	uniqueName := fmt.Sprintf("%s-%s-%s-%s", dtc.JobName, dtc.TaskGroupName, dtc.Name, dtc.AllocID[:8])

	// Package
	pkg, err := c.getPackage(cfg.Package)
	if err != nil {
		return nil, err
	}

	// Networks
	networks, err := c.getNetworks(cfg.Cloud.Networks)
	if err != nil {
		return nil, err
	}

	// Image
	image, err := c.getImage(cfg.Cloud.Image)
	if err != nil {
		return nil, err
	}

	return &tritonInstanceInput{
		tritonInput: &compute.CreateInstanceInput{
			Name:            uniqueName,
			Image:           image,
			Package:         pkg.ID,
			Networks:        networks,
			Tags:            cfg.Tags,
			Metadata:        metadata,
			Affinity:        cfg.Affinity,
			FirewallEnabled: cfg.FWEnabled,
		},
		apitype: "cloudapi",
	}, nil
}

func (c tritonClient) buildDockerAPIInput(ctx context.Context, dtc *drivers.TaskConfig, cfg TaskConfig) (*tritonInstanceInput, error) {
	c.logger.Info("building input for DockerAPI")

	// Handle Restart Policy For Docker
	var restartPolicy docker.RestartPolicy
	switch cfg.Docker.RestartPolicy {
	case "":
		restartPolicy = docker.AlwaysRestart()
	case "Always":
		restartPolicy = docker.AlwaysRestart()
	case "Never":
		restartPolicy = docker.NeverRestart()
	case "OnFailure":
		restartPolicy = docker.RestartOnFailure(100)
	}

	// Handle Docker Env
	metadata := make(map[string]string)
	var dockerEnv []string
	for k, v := range dtc.Env {
		switch k {
		case "NOMAD_META_MY_KEY":
			metadata[k] = v
		case "NOMAD_META_my_key":
			metadata[k] = v
		default:
			dockerEnv = append(dockerEnv, fmt.Sprintf("%s=%s", k, v))
		}

		dockerEnv = append(dockerEnv, fmt.Sprintf("%s=%s", k, v))
	}

	// Handle Docker Labels
	labels := make(map[string]string)
	for k, v := range cfg.Docker.Labels {
		labels[k] = v
	}

	// Add Affinity Rule to DockerEnv,  Currently the user is responsibile for supplying the affinity: prefix
	dockerEnv = append(dockerEnv, cfg.Affinity...)

	// Handle CNS
	if len(cfg.CNS) > 0 {
		labels["triton.cns.services"] = fmt.Sprintf(strings.Join(cfg.CNS, ","))
	}

	// Make Name Reflect the Nomad Spec
	uniqueName := fmt.Sprintf("%s-%s-%s-%s", dtc.JobName, dtc.TaskGroupName, dtc.Name, dtc.AllocID[:8])

	// Handle Package
	pkg, err := c.getPackage(cfg.Package)
	if err != nil {
		return nil, err
	}
	labels["com.joyent.package"] = pkg.ID

	// Public Network Setting
	if cfg.Docker.PublicNetwork != "" {
		labels["triton.network.public"] = cfg.Docker.PublicNetwork
	}

	// PortMapping
	portBindings := make(map[docker.Port][]docker.PortBinding)

	if len(cfg.Docker.Ports.TCP) > 0 {
		for _, v := range cfg.Docker.Ports.TCP {
			port := docker.Port(fmt.Sprintf("%d/tcp", v))
			portBindings[port] = []docker.PortBinding{
				docker.PortBinding{
					HostIP:   "0.0.0.0",
					HostPort: fmt.Sprintf("%d", v),
				},
			}
		}
	}
	if len(cfg.Docker.Ports.UDP) > 0 {
		for _, v := range cfg.Docker.Ports.UDP {
			port := docker.Port(fmt.Sprintf("%d/udp", v))
			portBindings[port] = []docker.PortBinding{
				docker.PortBinding{
					HostIP:   "0.0.0.0",
					HostPort: fmt.Sprintf("%d", v),
				},
			}
		}
	}

	// Handle Missing Tag
	if cfg.Docker.Image.Tag == "" {
		cfg.Docker.Image.Tag = "latest"
	}

	// See if AutoPull is set and if so configure
	var pullImgOpts docker.PullImageOptions
	var authConfig docker.AuthConfiguration

	if cfg.Docker.Image.AutoPull == true {
		pullImgOpts = docker.PullImageOptions{
			Repository: cfg.Docker.Image.Name,
			Tag:        cfg.Docker.Image.Tag,
			Context:    ctx,
		}

		// Handle external registry authentication
		auth, err := resolveRegistryAuthentication(&cfg)
		if err != nil {
			c.logger.Warn("Failed to find docker repo auth", "repo", cfg.Docker.Image.Name, "error", err)
			//return nil, err
		}

		if !authIsEmpty(auth) {
			c.logger.Debug("did not find docker auth for repo", "repo", cfg.Docker.Image.Name)
			authConfig = *auth
		}

	}

	// Put image into image:tag format
	image := fmt.Sprintf("%s:%s", cfg.Docker.Image.Name, cfg.Docker.Image.Tag)

	return &tritonInstanceInput{
		dockerInput: &docker.CreateContainerOptions{
			Name: uniqueName,
			Config: &docker.Config{
				Cmd:        cfg.Docker.Cmd,
				Entrypoint: cfg.Docker.Entrypoint,
				Env:        dockerEnv,
				Image:      image,
				Labels:     labels,
				OpenStdin:  cfg.Docker.OpenStdin,
				StdinOnce:  cfg.Docker.StdInOnce,
				Tty:        cfg.Docker.TTY,
				WorkingDir: cfg.Docker.WorkingDir,
				Hostname:   cfg.Docker.Hostname,
				Domainname: cfg.Docker.Domainname,
				User:       cfg.Docker.User,
			},
			HostConfig: &docker.HostConfig{
				NetworkMode:     cfg.Docker.PrivateNetwork,
				RestartPolicy:   restartPolicy,
				PortBindings:    portBindings,
				PublishAllPorts: cfg.Docker.Ports.PublishAll,
				DNS:             cfg.Docker.DNS,
				DNSSearch:       cfg.Docker.DNSSearch,
				ExtraHosts:      cfg.Docker.ExtraHosts,
				LogConfig:       docker.LogConfig(cfg.Docker.LogConfig),
			},
			Context: ctx,
		},
		dockerPullImgOpts: &pullImgOpts,
		dockerAuthConfig:  &authConfig,
		dockerMdata:       metadata,
		apitype:           "dockerapi",
	}, nil
}

// StopTask satisfies the triton.tritonClientInterface StopTask interface function.
func (c tritonClient) StopTask(ctx context.Context, instUUID string) error {
	cmpt, err := c.tclient.Compute()
	if err != nil {
		return err
	}

	// Stop the Instance
	if err := cmpt.Instances().Stop(ctx, &compute.StopInstanceInput{InstanceID: instUUID}); err != nil {
		return err
	}
        err = c.waitForInstState(cmpt, instUUID, "stopped", 60)
	if err != nil {
		return err
	}

	return nil
}

// DestroyTask satisfies the triton.tritonClientInterface DestroyTask interface function.
func (c tritonClient) DestroyTask(ctx context.Context, instUUID string) error {
	cmpt, err := c.tclient.Compute()
	if err != nil {
		return err
	}

	// Delete the Instance
	if err := cmpt.Instances().Delete(ctx, &compute.DeleteInstanceInput{ID: instUUID}); err != nil {
		return err
	}
        err = c.waitForInstState(cmpt, instUUID, "deleted", 60)
	if err != nil {
		return err
	}

	return nil
}

func (c tritonClient) getPackage(p Package) (*compute.Package, error) {
	client, err := c.tclient.Compute()
	if err != nil {
		return nil, err
	}

	input := &compute.ListPackagesInput{}

	_, err = uuid.FromString(p.Name)
	if err == nil {
		return &compute.Package{ID: p.Name}, nil
	}

	if p.Name != "" {
		input.Name = p.Name
	}

	if p.Version != "" {
		input.Version = p.Version
	}

	pkg, err := client.Packages().List(context.Background(), input)
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

func (c *tritonClient) getNetworks(ns []Network) ([]string, error) {
	n, err := c.tclient.Network()
	if err != nil {
		return nil, err
	}

	// UUID Provided as Name
	var networks []string
	for _, v := range ns {
		_, err := uuid.FromString(v.Name)
		if err == nil {
			networks = append(networks, v.Name)
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
	if len(networks) > 0 {
		return networks, nil
	}

	return nil, nil
}

func (c *tritonClient) getImage(i CloudImage) (string, error) {
	cmpt, err := c.tclient.Compute()
	if err != nil {
		return "", err
	}

	input := &compute.ListImagesInput{}

	_, err = uuid.FromString(i.Name)
	if err == nil {
		return i.Name, nil
	}

	if i.Name != "" {
		input.Name = i.Name
	}

	if i.Version != "" {
		input.Version = i.Version
	}

	images, err := cmpt.Images().List(context.Background(), input)
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

// authBackend encapsulates a function that resolves registry credentials.
type authBackend func(string) (*docker.AuthConfiguration, error)

// resolveRegistryAuthentication attempts to retrieve auth credentials for the
// repo, trying all authentication-backends possible.
func resolveRegistryAuthentication(cfg *TaskConfig) (*docker.AuthConfiguration, error) {
	return firstValidAuth(cfg.Docker.Image.Name, []authBackend{
		authFromTaskConfig(cfg),
	})
}

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
func authFromTaskConfig(cfg *TaskConfig) authBackend {
	return func(string) (*docker.AuthConfiguration, error) {
		// If all auth fields are empty, return
		if cfg.Docker.Auth.Username == "" && cfg.Docker.Auth.Password == "" && cfg.Docker.Auth.Email == "" && cfg.Docker.Auth.ServerAddr == "" {
			return nil, fmt.Errorf("No Docker Authenitcation Provided")
		}
		return &docker.AuthConfiguration{
			Username:      cfg.Docker.Auth.Username,
			Password:      cfg.Docker.Auth.Password,
			Email:         cfg.Docker.Auth.Email,
			ServerAddress: cfg.Docker.Auth.ServerAddr,
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

func dockerImageRef(repo string, tag string) string {
	if tag == "" {
		return repo
	}
	return fmt.Sprintf("%s:%s", repo, tag)
}

func (c *tritonClient) waitForInstState(cmpt *compute.ComputeClient, uuid string, state string, timeout int) error {
	var current int
	for {
		running, _ := cmpt.Instances().Get(context.Background(), &compute.GetInstanceInput{ID: uuid})
		if running != nil {
			if running.State == state {
				break
			}
			if current > timeout {
				errMsg := fmt.Errorf("Timeout exceeded while waiting for Inst: %s to be State: %s", uuid, state)
				return errMsg
			}
			time.Sleep(5 * time.Second)
			current = current + 5
		}
	}
	return nil
}
