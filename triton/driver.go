package triton

import (
	"context"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"time"

	"github.com/Smithx10/nomad-driver-triton/client"
	docker "github.com/fsouza/go-dockerclient"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/client/structs"
	"github.com/hashicorp/nomad/drivers/shared/eventer"
	"github.com/hashicorp/nomad/plugins/base"
	"github.com/hashicorp/nomad/plugins/drivers"
	"github.com/hashicorp/nomad/plugins/shared/hclspec"
	pstructs "github.com/hashicorp/nomad/plugins/shared/structs"
	"github.com/joyent/triton-go"
	"github.com/joyent/triton-go/authentication"
)

const (
	// pluginName is the name of the plugin
	pluginName = "triton"

	// pluginVersion allows the client to identify and use newer versions of
	// an installed plugin.
	pluginVersion = "v0.1.0"

	// fingerprintPeriod is the interval at which the driver will send fingerprint responses
	fingerprintPeriod = 30 * time.Second

	// taskHandleVersion is the version of task handle which this driver sets
	// and understands how to decode driver state
	taskHandleVersion = 1
)

var (
	// pluginInfo is the response returned for the PluginInfo RPC
	pluginInfo = &base.PluginInfoResponse{
		Type:              base.PluginTypeDriver,
		PluginApiVersions: []string{drivers.ApiVersion010},
		PluginVersion:     pluginVersion,
		Name:              pluginName,
	}

	// pluginConfigSpec is the hcl specification returned by the ConfigSchema RPC.
	pluginConfigSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"enabled":   hclspec.NewAttr("enabled", "bool", false),
		"cloudapi":  hclspec.NewAttr("cloudapi", "bool", false),
		"dockerapi": hclspec.NewAttr("dockerapi", "bool", false),
		"cluster":   hclspec.NewAttr("cluster", "string", false),
		"region":    hclspec.NewAttr("region", "string", false),
	})

	// taskConfigSpec is the hcl specification for the driver config section of
	// a task within a job. It is returned in the TaskConfigSchema RPC
	taskConfigSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"docker_api": hclspec.NewBlock("docker_api", false, hclspec.NewObject(map[string]*hclspec.Spec{
			"cmd":             hclspec.NewAttr("cmd", "list(string)", false),
			"entrypoint":      hclspec.NewAttr("entrypoint", "list(string)", false),
			"openstdin":       hclspec.NewAttr("openstdin", "bool", false),
			"stdinonce":       hclspec.NewAttr("stdinonce", "bool", false),
			"tty":             hclspec.NewAttr("tty", "bool", false),
			"workingdir":      hclspec.NewAttr("workingdir", "string", false),
			"hostname":        hclspec.NewAttr("hostname", "string", false),
			"dns":             hclspec.NewAttr("dns", "list(string)", false),
			"dns_search":      hclspec.NewAttr("dns_search", "list(string)", false),
			"extra_hosts":     hclspec.NewAttr("extra_hosts", "list(string)", false),
			"user":            hclspec.NewAttr("user", "string", false),
			"domain_name":     hclspec.NewAttr("domain_name", "string", false),
			"labels":          hclspec.NewBlockAttrs("labels", "string", false),
			"public_network":  hclspec.NewAttr("public_network", "string", false),
			"private_network": hclspec.NewAttr("private_network", "string", false),
			"log_config": hclspec.NewBlock("log_config", false, hclspec.NewObject(map[string]*hclspec.Spec{
				"type":   hclspec.NewAttr("type", "string", false),
				"config": hclspec.NewBlockAttrs("config", "string", false),
			})),
			"ports": hclspec.NewBlock("ports", false, hclspec.NewObject(map[string]*hclspec.Spec{
				"tcp":         hclspec.NewAttr("tcp", "list(number)", false),
				"udp":         hclspec.NewAttr("udp", "list(number)", false),
				"publish_all": hclspec.NewAttr("publish_all", "bool", false),
			})),
			"image": hclspec.NewBlock("image", true, hclspec.NewObject(map[string]*hclspec.Spec{
				"name":      hclspec.NewAttr("name", "string", true),
				"tag":       hclspec.NewAttr("tag", "string", false),
				"auto_pull": hclspec.NewAttr("auto_pull", "bool", false),
			})),
			"auth": hclspec.NewBlock("auth", false, hclspec.NewObject(map[string]*hclspec.Spec{
				"username":       hclspec.NewAttr("username", "string", false),
				"password":       hclspec.NewAttr("password", "string", false),
				"email":          hclspec.NewAttr("email", "string", false),
				"server_address": hclspec.NewAttr("server_address", "string", false),
			})),
			"restart_policy": hclspec.NewAttr("restart_policy", "string", false),
		})),
		"cloud_api": hclspec.NewBlock("cloud_api", false, hclspec.NewObject(map[string]*hclspec.Spec{
			"image": hclspec.NewBlock("image", true, hclspec.NewObject(map[string]*hclspec.Spec{
				"name":        hclspec.NewAttr("name", "string", false),
				"version":     hclspec.NewAttr("version", "string", false),
				"most_recent": hclspec.NewAttr("most_recent", "bool", false),
			})),
			"networks": hclspec.NewBlockList("networks", hclspec.NewObject(map[string]*hclspec.Spec{
				"name": hclspec.NewAttr("name", "string", false),
			})),
			"user_data":    hclspec.NewAttr("user_data", "string", false),
			"cloud_config": hclspec.NewAttr("cloud_config", "string", false),
			"user_script":  hclspec.NewAttr("user_script", "string", false),
		})),
		"tags":                hclspec.NewBlockAttrs("tags", "string", false),
		"affinity":            hclspec.NewAttr("affinity", "list(string)", false),
		"deletion_protection": hclspec.NewAttr("deletion_protection", "bool", false),
		"fwenabled":           hclspec.NewAttr("fwenabled", "bool", false),
		"fwrules":             hclspec.NewBlockAttrs("fwrules", "string", false),
		"cns":                 hclspec.NewAttr("cns", "list(string)", false),
		"package": hclspec.NewBlock("package", true, hclspec.NewObject(map[string]*hclspec.Spec{
			"name":    hclspec.NewAttr("name", "string", false),
			"version": hclspec.NewAttr("version", "string", false),
		})),
		"exit_strategy": hclspec.NewAttr("exit_strategy", "string", false),
	})

	// capabilities is returned by the Capabilities RPC and indicates what
	// optional features this driver supports
	capabilities = &drivers.Capabilities{
		SendSignals: true,
		Exec:        false,
		FSIsolation: drivers.FSIsolationImage,
		RemoteTasks: true,
	}
)

// Driver is a driver for running Triton Instances
type Driver struct {
	// eventer is used to handle multiplexing of TaskEvents calls such that an
	// event can be broadcast to all callers
	eventer *eventer.Eventer

	// config is the driver configuration set by the SetConfig RPC
	config *DriverConfig

	// nomadConfig is the client config from nomad
	nomadConfig *base.ClientDriverConfig

	// tasks is the in memory datastore mapping taskIDs to driverHandles
	tasks *taskStore

	// ctx is the context for the driver. It is passed to other subsystems to
	// coordinate shutdown
	ctx context.Context

	// signalShutdown is called when the driver is shutting down and cancels the
	// ctx passed to any subsystems
	signalShutdown context.CancelFunc

	// logger will log to the plugin output which is usually an 'executor.out'
	// file located in the root of the TaskDir
	logger hclog.Logger

	// tritonClientInterface is the interface used for communicating with Joyent Triton
	client tritonClientInterface
}

// DriverConfig is the driver configuration set by the SetConfig RPC call
type DriverConfig struct {
	Cluster          string `codec:"cluster"`
	Enabled          bool   `codec:"enabled"`
	CloudAPIEnabled  bool   `codec:"cloudapi"`
	DockerAPIEnabled bool   `codec:"dockerapi"`
	Region           string `codec:"region"`
}

type TaskConfig struct {
	Affinity           []string          `codec:"affinity" json:"affinity"`
	CNS                []string          `codec:"cns" json:"cns"`
	Cloud              CloudAPI          `codec:"cloud_api" json:"cloud_api"`
	DeletionProtection bool              `codec:"deletion_protection" json:"deletion_protection"`
	Docker             DockerAPI         `codec:"docker_api" json:"docker_api"`
	ExitStrategy       string            `codec:"exit_strategy" json:"exit_strategy"`
	FWEnabled          bool              `codec:"fwenabled" json:"fwenabled"`
	FWRules            map[string]string `codec:"fwrules" json:"fwrules"`
	Package            Package           `codec:"package" json:"package"`
	Tags               map[string]string `codec:"tags" json:"tags"`
}

type CloudAPI struct {
	CloudConfig string     `codec:"cloud_config" json:"cloud_config"`
	Image       CloudImage `codec:"image" json:"image"`
	Networks    []Network  `codec:"networks" json:"networks"`
	UserData    string     `codec:"user_data" json:"user_data"`
	UserScript  string     `codec:"user_script" json:"user_script"`
}

type Network struct {
	Name string `codec:"name" json:"name"`
}

type DockerAuth struct {
	Username   string `codec:"username"`
	Password   string `codec:"password"`
	Email      string `codec:"email"`
	ServerAddr string `codec:"server_address"`
}

type DockerImage struct {
	Name     string `codec:"name" json:"name"`
	Tag      string `codec:"tag" json:"tag"`
	AutoPull bool   `codec:"auto_pull" json:"auto_pull"`
}

type Package struct {
	Name    string `codec:"name" json:"name"`
	Version string `codec:"version" json:"version"`
}

type CloudImage struct {
	Name       string `codec:"name" json:"name"`
	MostRecent bool   `codec:"most_recent" json:"most_recent"`
	Version    string `codec:"version" json:"version"`
}

type Ports struct {
	TCP        []int `codec:"tcp" json:"tcp"`
	UDP        []int `codec:"udp" json:"udp"`
	PublishAll bool  `codec:"publish_all" json:"publish_all"`
}

type LogConfig struct {
	Type   string            `codec:"type" json:"type"`
	Config map[string]string `codec:"config" json:"config"`
}

type DockerAPI struct {
	Cmd            []string          `codec:"cmd" json:"cmd"`
	Entrypoint     []string          `codec:"entrypoint" json:"entrypoint"`
	OpenStdin      bool              `codec:"openstdin" json:"openstdin"`
	StdInOnce      bool              `codec:"stdinonce" json:"stdinonce"`
	TTY            bool              `codec:"tty" json:"tty"`
	WorkingDir     string            `codec:"workingdir" json:"workingdir"`
	Image          DockerImage       `codec:"image" json:"image"`
	Auth           DockerAuth        `codec:"auth"`
	Labels         map[string]string `codec:"labels" json:"labels"`
	PublicNetwork  string            `codec:"public_network" json:"public_network"`
	PrivateNetwork string            `codec:"private_network" json:"private_network"`
	RestartPolicy  string            `codec:"restart_policy" json:"restart_policy"`
	Ports          Ports             `codec:"ports" json:"ports"`
	Hostname       string            `codec:"hostname" json:"hostname"`
	DNS            []string          `codec:"dns" json:"dns"`
	DNSSearch      []string          `codec:"dns_search" json:"dns_search"`
	User           string            `codec:"user" json:"user"`
	Domainname     string            `codec:"domain_name" json:"domain_name"`
	ExtraHosts     []string          `codec:"extra_hosts" json:"extra_hosts"`
	LogConfig      LogConfig         `codec:"log_config" json:"log_config"`
}

// TaskState is the state which is encoded in the handle returned in
// StartTask. This information is needed to rebuild the task state and handler
// during recovery.
type TaskState struct {
	TaskConfig   *drivers.TaskConfig
	InstUUID     string
	InstanceName string
	StartedAt    time.Time
}

// NewPlugin returns a new DriverPlugin implementation
func NewPlugin(logger hclog.Logger) drivers.DriverPlugin {
	ctx, cancel := context.WithCancel(context.Background())
	logger = logger.Named(pluginName)

	return &Driver{
		eventer:        eventer.NewEventer(ctx, logger),
		config:         &DriverConfig{},
		tasks:          newTaskStore(),
		ctx:            ctx,
		signalShutdown: cancel,
		logger:         logger,
	}
}

func (*Driver) PluginInfo() (*base.PluginInfoResponse, error) {
	return pluginInfo, nil
}

func (*Driver) ConfigSchema() (*hclspec.Spec, error) {
	return pluginConfigSpec, nil
}

func (d *Driver) SetConfig(cfg *base.Config) error {
	d.logger.Info("Inside SetConfig")
	var config DriverConfig
	if len(cfg.PluginConfig) != 0 {
		if err := base.MsgPackDecode(cfg.PluginConfig, &config); err != nil {
			return err
		}
	}

	d.config = &config
	if cfg.AgentConfig != nil {
		d.nomadConfig = cfg.AgentConfig.Driver
	}

	client, err := d.newTritonClient(d.logger)
	if err != nil {
		return fmt.Errorf("failed to create Triton client: %v", err)
	}

	d.client = client

	return nil
}

func (d *Driver) newTritonClient(logger hclog.Logger) (tritonClientInterface, error) {
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

	return tritonClient{
		tclient: &client.Client{
			Config:                tritonConfig,
			InsecureSkipTLSVerify: insecure,
			AffinityLock:          &sync.RWMutex{},
		},
		dclient: dockerClient,
		logger:  logger,
	}, nil

}

func (d *Driver) Shutdown(ctx context.Context) error {
	d.signalShutdown()
	return nil
}

func (d *Driver) TaskConfigSchema() (*hclspec.Spec, error) {
	return taskConfigSpec, nil
}

func (d *Driver) Capabilities() (*drivers.Capabilities, error) {
	return capabilities, nil
}

func (d *Driver) Fingerprint(ctx context.Context) (<-chan *drivers.Fingerprint, error) {
	ch := make(chan *drivers.Fingerprint)
	go d.handleFingerprint(ctx, ch)
	return ch, nil
}

func (d *Driver) handleFingerprint(ctx context.Context, ch chan<- *drivers.Fingerprint) {
	defer close(ch)
	ticker := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ticker.Reset(fingerprintPeriod)
			ch <- d.buildFingerprint(ctx)
		}
	}
}

func (d *Driver) buildFingerprint(ctx context.Context) *drivers.Fingerprint {
	var health drivers.HealthState
	var desc string
	attrs := map[string]*pstructs.Attribute{}

	d.logger.Info("Inside buildFingerprint", d.config)
	if d.config.Enabled {
		if err := d.client.DescribeCluster(ctx); err != nil {
			d.logger.Info("Error on Describe")
			health = drivers.HealthStateUnhealthy
			desc = err.Error()
			attrs["driver.triton"] = pstructs.NewBoolAttribute(false)
		} else {
			d.logger.Info("pass on Describe")
			health = drivers.HealthStateHealthy
			desc = "Healthy"
			attrs["driver.triton"] = pstructs.NewBoolAttribute(true)
		}
	} else {
		health = drivers.HealthStateUndetected
		desc = "disabled"
	}

	return &drivers.Fingerprint{
		Attributes:        attrs,
		Health:            health,
		HealthDescription: desc,
	}
}

func (d *Driver) RecoverTask(handle *drivers.TaskHandle) error {
	d.logger.Info("Inside RecoverTask")
	d.logger.Info("recovering triton instance", "version", handle.Version,
		"task_config.id", handle.Config.ID, "task_state", handle.State,
		"driver_state_bytes", len(handle.DriverState))
	if handle == nil {
		return fmt.Errorf("handle cannot be nil")
	}

	// If already attached to handle there's nothing to recover.
	if _, ok := d.tasks.Get(handle.Config.ID); ok {
		d.logger.Info("no triton instance to recover; task already exists",
			"task_id", handle.Config.ID,
			"task_name", handle.Config.Name,
		)
		return nil
	}

	// Handle doesn't already exist, try to reattach
	var taskState TaskState
	if err := handle.GetDriverState(&taskState); err != nil {
		d.logger.Error("failed to decode task state from handle", "error", err, "task_id", handle.Config.ID)
		return fmt.Errorf("failed to decode task state from handle: %v", err)
	}

	d.logger.Info("triton instance recovered", "instUUID", taskState.InstUUID,
		"started_at", taskState.StartedAt)

	h := newTaskHandle(d.logger, d.eventer, taskState, handle.Config, d.client)

	d.tasks.Set(handle.Config.ID, h)

	go h.run()
	return nil
}

func (d *Driver) StartTask(cfg *drivers.TaskConfig) (*drivers.TaskHandle, *drivers.DriverNetwork, error) {
	d.logger.Info("Inside StartTask")
	if !d.config.Enabled {
		return nil, nil, fmt.Errorf("disabled")
	}

	if _, ok := d.tasks.Get(cfg.ID); ok {
		return nil, nil, fmt.Errorf("task with ID %q already started", cfg.ID)
	}

	var driverConfig TaskConfig
	if err := cfg.DecodeDriverConfig(&driverConfig); err != nil {
		return nil, nil, fmt.Errorf("failed to decode driver config: %v", err)
	}

	d.logger.Info("starting triton instance", "driver_cfg", hclog.Fmt("%+v", driverConfig))
	handle := drivers.NewTaskHandle(taskHandleVersion)
	handle.Config = cfg

	instUUID, driverNetwork, err := d.client.RunTask(context.Background(), cfg, driverConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start Triton instance: %v", err)
	}

	driverState := TaskState{
		TaskConfig: cfg,
		StartedAt:  time.Now(),
		InstUUID:   instUUID,
	}

	d.logger.Info("triton instance started", "instuuid", driverState.InstUUID, "started_at", driverState.StartedAt)

	h := newTaskHandle(d.logger, d.eventer, driverState, cfg, d.client)

	if err := handle.SetDriverState(&driverState); err != nil {
		d.logger.Error("failed to start task, error setting driver state", "error", err)
		h.stop(false)
		return nil, nil, fmt.Errorf("failed to set driver state: %v", err)
	}

	d.tasks.Set(cfg.ID, h)

	go h.run()
	return handle, driverNetwork, nil
}

func (d *Driver) WaitTask(ctx context.Context, taskID string) (<-chan *drivers.ExitResult, error) {
	d.logger.Info("WaitTask() called", "task_id", taskID)
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	ch := make(chan *drivers.ExitResult)
	go d.handleWait(ctx, handle, ch)

	return ch, nil
}

func (d *Driver) handleWait(ctx context.Context, handle *taskHandle, ch chan *drivers.ExitResult) {
	defer close(ch)

	var result *drivers.ExitResult
	select {
	case <-ctx.Done():
		return
	case <-d.ctx.Done():
		return
	case <-handle.doneCh:
		result = &drivers.ExitResult{
			ExitCode: handle.exitResult.ExitCode,
			Signal:   handle.exitResult.Signal,
			Err:      nil,
		}
	}

	select {
	case <-ctx.Done():
		return
	case <-d.ctx.Done():
		return
	case ch <- result:
	}
}

func (d *Driver) StopTask(taskID string, timeout time.Duration, signal string) error {
	d.logger.Info("Inside StopTask")
	d.logger.Info("stopping triton instance", "task_id", taskID, "timeout", timeout, "signal", signal)
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	// Detach if that's the signal, otherwise kill
	detach := signal == drivers.DetachSignal
	handle.stop(detach)

	// Wait for handle to finish
	select {
	case <-handle.doneCh:
	case <-time.After(timeout):
		return fmt.Errorf("timed out waiting for triton task (id=%s) to stop (detach=%t)",
			taskID, detach)
	}

	d.logger.Info("triton task stopped", "task_id", taskID, "timeout", timeout,
		"signal", signal)
	return nil
}

func (d *Driver) DestroyTask(taskID string, force bool) error {
	d.logger.Info("Inside DestroyTask")
	d.logger.Info("destroying triton task", "task_id", taskID, "force", force)
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	if handle.IsRunning() && !force {
		return fmt.Errorf("cannot destroy running task")
	}

	// Safe to always kill here as detaching will have already happened
	handle.stop(false)

	if !handle.detach {
		if err := handle.destroyTask(); err != nil {
			return err
		}
	}

	d.tasks.Delete(taskID)
	d.logger.Info("triton instance destroyed", "task_id", taskID, "force", force)
	return nil
}

func (d *Driver) InspectTask(taskID string) (*drivers.TaskStatus, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}
	return handle.TaskStatus(), nil
}

func (d *Driver) TaskStats(ctx context.Context, taskID string, interval time.Duration) (<-chan *structs.TaskResourceUsage, error) {
	d.logger.Info("sending triton instance stats", "task_id", taskID)
	_, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	ch := make(chan *drivers.TaskResourceUsage)

	go func() {
		defer d.logger.Info("stopped sending triton instance stats", "task_id", taskID)
		defer close(ch)
		for {
			select {
			case <-time.After(interval):

				// Nomad core does not currently have any resource based
				// support for remote drivers. Once this changes, we may be
				// able to report actual usage here.
				//
				// This is required, otherwise the driver panics.
				ch <- &structs.TaskResourceUsage{
					ResourceUsage: &drivers.ResourceUsage{
						MemoryStats: &drivers.MemoryStats{},
						CpuStats:    &drivers.CpuStats{},
					},
					Timestamp: time.Now().UTC().UnixNano(),
				}
			case <-ctx.Done():
				return
			}

		}
	}()

	return ch, nil
}

func (d *Driver) TaskEvents(ctx context.Context) (<-chan *drivers.TaskEvent, error) {
	d.logger.Info("retrieving task events")
	return d.eventer.TaskEvents(ctx)
}

func (d *Driver) SignalTask(taskID string, signal string) error {
	d.logger.Info("Inside SignalTask")
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}
	instUUID := handle.instUUID

	switch signal {
	case "reboot":
		handle.rebooting = true
		if err := d.client.RebootTask(context.Background(), instUUID); err != nil {
			handle.rebooting = false
			return err
		}
		handle.rebooting = false
	}

	return nil
}

func (d *Driver) ExecTask(_ string, _ []string, _ time.Duration) (*drivers.ExecTaskResult, error) {
	return nil, fmt.Errorf("Triton driver does not support exec")
}
