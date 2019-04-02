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
		PluginVersion:     "0.0.1",
		Name:              pluginName,
	}

	// configSpec is the hcl specification returned by the ConfigSchema RPC
	configSpec = hclspec.NewObject(map[string]*hclspec.Spec{})

	// taskConfigSpec is the hcl specification for the driver config section of
	// a task within a job. It is returned in the TaskConfigSchema RPC
	taskConfigSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"image":        hclspec.NewAttr("image", "string", true),
		"package":      hclspec.NewAttr("package", "string", true),
		"networks":     hclspec.NewAttr("networks", "list(string)", true),
		"user_data":    hclspec.NewAttr("user_data", "string", false),
		"cloud_config": hclspec.NewAttr("cloud_config", "string", false),
		"user_script":  hclspec.NewAttr("user_script", "string", false),
		"tags":         hclspec.NewBlockAttrs("tags", "string", false),
		"affinity":     hclspec.NewAttr("affinity", "string", false),
		"fwenabled":    hclspec.NewAttr("fwenabled", "bool", false),
		"fwrules":      hclspec.NewBlockAttrs("fwrules", "string", false),
		"cns":          hclspec.NewAttr("cns", "list(string)", false),
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
	Affinity    string            `codec:"affinity"`
	CloudConfig string            `codec:"cloud_config"`
	CNS         []string          `codec:"cns"`
	FWEnabled   bool              `codec:"fwenabled"`
	FWRules     map[string]string `codec:"fwrules"`
	Image       string            `codec:"image"`
	Networks    []string          `codec:"networks"`
	Package     string            `codec:"package"`
	Tags        map[string]string `codec:"tags"`
	UserData    string            `codec:"user_data"`
	UserScript  string            `codec:"user_script"`
}

// TaskState is the state which is encoded in the handle returned in
// StartTask. This information is needed to rebuild the task state and handler
// during recovery.
type TaskState struct {
	TaskConfig *drivers.TaskConfig
	TritonTask *TritonTask
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

	d.logger.Warn("Set Config", "config", fmt.Sprintf("%#v", config), "raw", cfg.PluginConfig)

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

	d.logger.Info(fmt.Sprintf("HANDLESTATE: %s", taskState))

	c, err := d.tth.client.Compute()
	if err != nil {
		return err
	}

	d.logger.Info(fmt.Sprintf("COMPUTE: %s", c))

	pi, err := c.Instances().Get(context.Background(), &compute.GetInstanceInput{ID: taskState.TritonTask.instance.ID})
	if err != nil {
		return err
	}
	d.logger.Info(fmt.Sprintf("INSTANCE: %s", pi))

	nh := &taskHandle{
		tth:        d.tth,
		taskConfig: taskState.TaskConfig,
		tritonTask: taskState.TritonTask,
		procState:  drivers.TaskStateRunning,
		startedAt:  time.Now().Round(time.Millisecond),
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

	d.logger.Info("starting triton task", "driver_cfg", hclog.Fmt("%+v", config))

	handle := drivers.NewTaskHandle(taskHandleVersion)
	handle.Config = cfg

	d.logger.Info(fmt.Sprintln("CONFIG: ", config))

	// Create a Triton Task
	tt, err := d.tth.NewTritonTask(cfg, config)
	if err != nil {
		return nil, nil, err
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
		IP:            tt.instance.PrimaryIP,
		AutoAdvertise: true,
	}

	driverState := TaskState{
		TritonTask: tt,
		TaskConfig: cfg,
		StartedAt:  h.startedAt,
	}

	if err := handle.SetDriverState(&driverState); err != nil {
		d.logger.Error("failed to start task, error setting driver state", "error", err)
		//cleanup()
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
