package plugin

import (
	"context"
	"fmt"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/plugins/base"
	"github.com/hashicorp/nomad/plugins/drivers"
	"github.com/hashicorp/nomad/plugins/shared/hclspec"
	pstructs "github.com/hashicorp/nomad/plugins/shared/structs"
	"github.com/joyent/triton-go/compute"
	"github.com/joyent/triton-go/network"
)

const (
	// pluginName is the name of the plugin
	pluginName = "triton"

	// fingerprintPeriod is the interval at which the driver will send fingerprint responses
	fingerprintPeriod = 30 * time.Second

	// executableMask is the mask needed to check whether or not a file's
	// permissions are executable.
	executableMask = 0111

	// taskHandleVersion is the version of task handle which this driver sets
	// and understands how to decode driver state
	taskHandleVersion = 1
)

var (
	// pluginInfo is the response returned for the PluginInfo RPC
	pluginInfo = &base.PluginInfoResponse{
		Type:              base.PluginTypeDriver,
		PluginApiVersions: []string{"0.1.0"},
		PluginVersion:     "0.0.2",
		Name:              pluginName,
	}

	// configSpec is the hcl specification returned by the ConfigSchema RPC
	configSpec = hclspec.NewObject(map[string]*hclspec.Spec{})

	// taskConfigSpec is the hcl specification for the driver config section of
	// a task within a job. It is returned in the TaskConfigSchema RPC
	taskConfigSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"api_type": hclspec.NewAttr("api_type", "string", true),
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
			"restart_policy": hclspec.NewAttr("restart_policy", "string", false),
		})),
		"cloud_api": hclspec.NewBlock("cloud_api", false, hclspec.NewObject(map[string]*hclspec.Spec{
			"image": hclspec.NewBlock("image", true, hclspec.NewObject(map[string]*hclspec.Spec{
				"name":        hclspec.NewAttr("name", "string", false),
				"uuid":        hclspec.NewAttr("uuid", "string", false),
				"version":     hclspec.NewAttr("version", "string", false),
				"most_recent": hclspec.NewAttr("most_recent", "bool", false),
			})),
			"networks": hclspec.NewBlockList("networks", hclspec.NewObject(map[string]*hclspec.Spec{
				"name": hclspec.NewAttr("name", "string", false),
				"uuid": hclspec.NewAttr("uuid", "string", false),
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
			"uuid":    hclspec.NewAttr("uuid", "string", false),
			"version": hclspec.NewAttr("version", "string", false),
		})),
	})

	// capabilities is returned by the Capabilities RPC and indicates what
	// optional features this driver supports
	capabilities = &drivers.Capabilities{
		SendSignals: false,
		Exec:        false,
		FSIsolation: drivers.FSIsolationImage,
	}
)

type DriverConfig struct {
}

type TaskConfig struct {
	APIType            string            `codec:"api_type" json:"api_type"`
	Cloud              CloudAPI          `codec:"cloud_api" json:"cloud_api"`
	Docker             DockerAPI         `codec:"docker_api" json:"docker_api"`
	Affinity           []string          `codec:"affinity" json:"affinity"`
	CNS                []string          `codec:"cns" json:"cns"`
	DeletionProtection bool              `codec:"deletion_protection" json:"deletion_protection"`
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
	UUID string `codec:"uuid" json:"uuid"`
}

type DockerImage struct {
	Name     string `codec:"name" json:"name"`
	Tag      string `codec:"tag" json:"tag"`
	AutoPull bool   `codec:"auto_pull" json:"auto_pull"`
}

type Package struct {
	Name    string `codec:"name" json:"name"`
	UUID    string `codec:"uuid" json:"uuid"`
	Version string `codec:"version" json:"version"`
}

type CloudImage struct {
	Name       string `codec:"name" json:"name"`
	UUID       string `codec:"uuid" json:"uuid"`
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
	APIType    string
	TaskConfig *drivers.TaskConfig
	InstanceID string
	FWRules    []string
	StartedAt  time.Time
}

type Driver struct {
	// logger will log to the plugin output which is usually an 'executor.out'
	// file located in the root of the TaskDir
	logger hclog.Logger

	config *DriverConfig

	tth *TritonTaskHandler

	// tasks is the in memory datastore mapping taskIDs to driverHandles
	tasks *taskStore
}

var _ drivers.DriverPlugin = &Driver{}

func NewDriver(logger hclog.Logger) *Driver {
	logger = logger.Named(pluginName)

	return &Driver{
		logger: logger,
		tasks:  newTaskStore(),
		tth:    NewTritonTaskHandler(logger),
	}
}

func (*Driver) PluginInfo() (*base.PluginInfoResponse, error) {
	return pluginInfo, nil
}

func (*Driver) ConfigSchema() (*hclspec.Spec, error) {
	return configSpec, nil
}

func (d *Driver) SetConfig(cfg *base.Config) error {
	d.logger.Info("Inside SetConfig")

	var config DriverConfig
	if len(cfg.PluginConfig) != 0 {
		if err := base.MsgPackDecode(cfg.PluginConfig, &config); err != nil {
			return err
		}
	}

	//d.logger.Warn("Set Config", "config", fmt.Sprintf("%#v", config), "raw", cfg.PluginConfig)

	d.config = &config

	return nil
}

func (d *Driver) Shutdown(ctx context.Context) error {
	d.logger.Info("Inside Shutdown")
	return nil
}

func (d *Driver) TaskConfigSchema() (*hclspec.Spec, error) {
	d.logger.Info("Inside TaskConfigSchema")
	return taskConfigSpec, nil
}

func (d *Driver) Capabilities() (*drivers.Capabilities, error) {
	return capabilities, nil
}

func (d *Driver) Fingerprint(ctx context.Context) (<-chan *drivers.Fingerprint, error) {
	ch := make(chan *drivers.Fingerprint, 1)
	ch <- d.buildFingerprint()
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
			ch <- d.buildFingerprint()
			ticker.Reset(fingerprintPeriod)
		}
	}
}

func (d *Driver) fingerprintBinary(path string) *drivers.Fingerprint {
	return nil
}

func (d *Driver) buildFingerprint() *drivers.Fingerprint {
	health := drivers.HealthStateHealthy
	desc := "ready"
	attrs := map[string]*pstructs.Attribute{"driver.triton": pstructs.NewStringAttribute("1")}

	return &drivers.Fingerprint{
		Attributes:        attrs,
		Health:            health,
		HealthDescription: desc,
	}
}

func (d *Driver) RecoverTask(h *drivers.TaskHandle) error {
	// TODO Move this over to triton.go
	d.logger.Info("Inside RecoverTask")
	if h == nil {
		return fmt.Errorf("error: handle cannot be nil")
	}

	if _, ok := d.tasks.Get(h.Config.ID); ok {
		return nil
	}

	var taskState TaskState
	if err := h.GetDriverState(&taskState); err != nil {
		return fmt.Errorf("failed to decode task state from handle: %v", err)
	}

	//d.logger.Info(fmt.Sprintf("HANDLESTATE: %s", taskState))

	//d.logger.Info(fmt.Sprintf("TASKSTATE: %s", taskState))

	// Build Context
	ctx := context.Background()
	sctx, cancel := context.WithCancel(ctx)

	// Instance
	c, err := d.tth.client.Compute()
	if err != nil {
		return err
	}

	pi, err := c.Instances().Get(sctx, &compute.GetInstanceInput{ID: taskState.InstanceID})
	if err != nil {
		return err
	}

	n, err := d.tth.client.Network()
	if err != nil {
		return err
	}

	// FWRules
	var fwrules []*network.FirewallRule
	for _, v := range taskState.FWRules {
		pr, err := n.Firewall().GetRule(sctx, &network.GetRuleInput{
			ID: v,
		})
		if err != nil {
			return err
		}
		fwrules = append(fwrules, pr)
	}

	tt := &TritonTask{
		Instance: pi,
		Ctx:      sctx,
		Shutdown: cancel,
		FWRules:  fwrules,
	}

	nh := &taskHandle{
		tth:        d.tth,
		taskConfig: taskState.TaskConfig,
		tritonTask: tt,
		procState:  drivers.TaskStateRunning,
		startedAt:  taskState.StartedAt,
		logger:     d.logger,
		waitCh:     make(chan struct{}),
	}

	d.tasks.Set(taskState.TaskConfig.ID, nh)

	go nh.run()

	return nil
}

func (d *Driver) StartTask(cfg *drivers.TaskConfig) (*drivers.TaskHandle, *drivers.DriverNetwork, error) {
	d.logger.Info("Inside StartTask")
	if _, ok := d.tasks.Get(cfg.ID); ok {
		return nil, nil, fmt.Errorf("task with ID %q already started", cfg.ID)
	}

	var config TaskConfig
	if err := cfg.DecodeDriverConfig(&config); err != nil {
		return nil, nil, err
	}

	switch config.APIType {
	case "docker_api":
		break
	case "cloud_api":
		break
	default:
		return nil, nil, fmt.Errorf("Must supply a api_type of either docker_api or cloud_api")
	}

	d.logger.Info("starting triton task", "driver_cfg", hclog.Fmt("%+v", config))

	handle := drivers.NewTaskHandle(taskHandleVersion)
	handle.Config = cfg

	// Create a Triton Task
	tt, err := d.tth.NewTritonTask(cfg, config)
	if err != nil {
		return nil, nil, err
	}

	var fwruleids []string
	for _, v := range tt.FWRules {
		fwruleids = append(fwruleids, v.ID)
	}

	h := &taskHandle{
		tth:        d.tth,
		taskConfig: cfg,
		tritonTask: tt,
		procState:  drivers.TaskStateRunning,
		startedAt:  time.Now().Round(time.Millisecond),
		logger:     d.logger,
		waitCh:     make(chan struct{}),
	}

	n := &drivers.DriverNetwork{
		IP:            tt.Instance.PrimaryIP,
		AutoAdvertise: true,
	}

	driverState := TaskState{
		APIType:    config.APIType,
		InstanceID: tt.Instance.ID,
		FWRules:    fwruleids,
		TaskConfig: cfg,
		StartedAt:  h.startedAt,
	}

	//d.logger.Info(fmt.Sprintf("DRIVERSTATE: %s", driverState))

	if err := handle.SetDriverState(&driverState); err != nil {
		d.logger.Error("failed to start task, error setting driver state", "error", err)
		return nil, nil, fmt.Errorf("failed to set driver state: %v", err)
	}

	d.tasks.Set(cfg.ID, h)

	go h.run()

	return handle, n, nil
}

func (d *Driver) WaitTask(ctx context.Context, taskID string) (<-chan *drivers.ExitResult, error) {
	d.logger.Info("Inside WaitTask")
	h, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, fmt.Errorf("task with ID %q not found", taskID)
	}

	ch := make(chan *drivers.ExitResult)
	go func(ch chan *drivers.ExitResult, task *taskHandle) {
		<-task.waitCh
		ch <- task.exitResult
	}(ch, h)

	return ch, nil
}

func (d *Driver) StopTask(taskID string, timeout time.Duration, signal string) error {
	d.logger.Info("Inside StopTask")
	h, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	if err := d.tth.ShutdownInstance(h.tritonTask); err != nil {
		return fmt.Errorf("executor Shutdown failed: %v", err)
	}

	return nil
}

func (d *Driver) DestroyTask(taskID string, force bool) error {
	d.logger.Info("Inside DestroyTask")
	h, ok := d.tasks.Get(taskID)

	if !ok {
		return drivers.ErrTaskNotFound
	}

	if !force {
		return fmt.Errorf("cannot destroy running task")
	}

	// grace period is chosen arbitrary here
	if err := d.tth.DestroyTritonTask(h, force); err != nil {
		h.logger.Error("failed to destroy executor", "err", err)
	}

	d.tasks.Delete(taskID)
	return nil
}

func (d *Driver) InspectTask(taskID string) (*drivers.TaskStatus, error) {
	d.logger.Info("Inside InspectTask")
	h, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, fmt.Errorf("task with ID %q not found", taskID)
	}

	return h.TaskStatus(), nil
}

func (d *Driver) TaskStats(ctx context.Context, taskID string, interval time.Duration) (<-chan *drivers.TaskResourceUsage, error) {
	d.logger.Info("Inside TaskStats")
	//h, ok := d.tasks.Get(taskID)
	//if !ok {
	//return nil, fmt.Errorf("task with ID %q not found", taskID)
	//}

	//return h.exec.Stats(ctx, interval)
	return nil, nil
}

func (d *Driver) TaskEvents(ctx context.Context) (<-chan *drivers.TaskEvent, error) {
	d.logger.Info("Inside TaskEvents")
	return make(chan *drivers.TaskEvent), nil
}

func (d *Driver) SignalTask(taskID string, signal string) error {
	d.logger.Info("Inside SignalTask")
	return nil
}

func (d *Driver) ExecTask(taskID string, cmd []string, timeout time.Duration) (*drivers.ExecTaskResult, error) {
	d.logger.Info("Inside ExecTask")
	return nil, nil
}
