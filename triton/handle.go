package triton

import (
	"context"
	"fmt"
	"sync"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/client/lib/fifo"
	"github.com/hashicorp/nomad/client/stats"
	"github.com/hashicorp/nomad/drivers/shared/eventer"
	"github.com/hashicorp/nomad/plugins/drivers"
)

const (
	tritonInstanceStatusDeleted     = "deleted"
	tritonInstanceStatusFailed      = "failed"
	tritonInstanceStatusProvisining = "provisining"
	tritonInstanceStatusRunning     = "running"
	tritonInstanceStatusStopped     = "stopped"
	tritonInstanceStatusStopping    = "stopping"
	tritonInstanceStatusUnknown     = "unkown"
)

type taskHandle struct {
	instUUID     string
	logger       hclog.Logger
	eventer      *eventer.Eventer
	tritonClient tritonClientInterface

	totalCpuStats  *stats.CpuStats
	userCpuStats   *stats.CpuStats
	systemCpuStats *stats.CpuStats

	// stateLock syncs access to all fields below
	stateLock sync.RWMutex

	taskConfig  *drivers.TaskConfig
	procState   drivers.TaskState
	startedAt   time.Time
	completedAt time.Time
	exitResult  *drivers.ExitResult
	doneCh      chan struct{}

	// detach from ecs task instead of killing it if true.
	detach    bool
	rebooting bool

	ctx    context.Context
	cancel context.CancelFunc
}

func newTaskHandle(logger hclog.Logger, eventer *eventer.Eventer, ts TaskState, taskConfig *drivers.TaskConfig, tritonClient tritonClientInterface) *taskHandle {
	ctx, cancel := context.WithCancel(context.Background())
	logger = logger.Named("handle").With("instuuid", ts.InstUUID)

	h := &taskHandle{
		instUUID:     ts.InstUUID,
		tritonClient: tritonClient,
		taskConfig:   taskConfig,
		procState:    drivers.TaskStateRunning,
		startedAt:    ts.StartedAt,
		exitResult:   &drivers.ExitResult{},
		logger:       logger,
		eventer:      eventer,
		doneCh:       make(chan struct{}),
		detach:       false,
		rebooting:    false,
		ctx:          ctx,
		cancel:       cancel,
	}

	return h
}

func (h *taskHandle) TaskStatus() *drivers.TaskStatus {
	h.stateLock.RLock()
	defer h.stateLock.RUnlock()

	return &drivers.TaskStatus{
		ID:          h.taskConfig.ID,
		Name:        h.taskConfig.Name,
		State:       h.procState,
		StartedAt:   h.startedAt,
		CompletedAt: h.completedAt,
		ExitResult:  h.exitResult,
		DriverAttributes: map[string]string{
			"instuuid": h.instUUID,
		},
	}
}

func (h *taskHandle) IsRunning() bool {
	h.stateLock.RLock()
	defer h.stateLock.RUnlock()
	return h.procState == drivers.TaskStateRunning
}

func (h *taskHandle) run() {
	defer close(h.doneCh)
	h.stateLock.Lock()
	if h.exitResult == nil {
		h.exitResult = &drivers.ExitResult{}
	}
	h.stateLock.Unlock()
	// prevStatus is used for Emitting Status changes.
	prevStatus := tritonInstanceStatusUnknown

	// Open the tasks StdoutPath so we can write task health status updates.
	f, err := fifo.OpenWriter(h.taskConfig.StdoutPath)
	if err != nil {
		h.handleRunError(err, "failed to open task stdout path")
		return
	}

	// Run the deferred close in an anonymous routine so we can see any errors.
	defer func() {
		if err := f.Close(); err != nil {
			h.logger.Error("failed to close task stdout handle correctly", "error", err)
		}
	}()

	// Block until stopped.
	for h.ctx.Err() == nil {
		select {
		case <-time.After(5 * time.Second):
			status, err := h.tritonClient.DescribeTaskStatus(h.ctx, h.instUUID)
			if prevStatus != status {
				h.eventer.EmitEvent(
					&drivers.TaskEvent{
						TaskID:    h.taskConfig.ID,
						TaskName:  h.taskConfig.Name,
						AllocID:   h.taskConfig.AllocID,
						Timestamp: time.Now(),
						Message:   fmt.Sprintf("Alloc Status changed from %s to %s.", prevStatus, status),
					})

				prevStatus = status
			}
			if err != nil {
				h.handleRunError(err, "failed to find Triton Instance")
				return
			}

			// Write the health status before checking what it is ensures the
			// alloc logs include the health during the Triton instance terminal
			// phase.
			now := time.Now().Format(time.RFC3339)
			if _, err := fmt.Fprintf(f, "[%s] - client is remotely monitoring Triton instance: %v with status %v\n",
				now, h.instUUID, status); err != nil {
				h.handleRunError(err, "failed to write to stdout")
			}

			// Triton instance has terminal status phase, meaning the task is going to
			// stop. If we are in this phase, the driver should exit and pass
			// this to the servers so that a new allocation, and ECS task can
			// be started.
			//if status == tritonInstanceStatusProvisining || status == tritonInstanceStatusStopping ||
			//status == tritonInstanceStatusDeleted || status == tritonInstanceStatusStopped {
			//h.handleRunError(fmt.Errorf("Triton instance status in terminal phase"), "task status: "+status)
			//return
			//}
			if !h.rebooting {
				if status == tritonInstanceStatusStopped {
					h.handleRunError(fmt.Errorf("Triton instance status in terminal phase"), "task status: "+status)
					return
				}
			}

		case <-h.ctx.Done():
			h.logger.Info("Inside run(ctx.Done())")
		}
	}

	h.stateLock.Lock()
	defer h.stateLock.Unlock()

	// Only stop task if we're not detaching.
	if !h.detach {
		if err := h.stopTask(); err != nil {
			h.handleRunError(err, "failed to stop Triton instance correctly")
			return
		}
	}

	h.procState = drivers.TaskStateExited
	h.exitResult.ExitCode = 0
	h.exitResult.Signal = 0
	h.completedAt = time.Now()
}

func (h *taskHandle) stop(detach bool) {
	h.logger.Info("Inside stop(detach)")
	h.stateLock.Lock()
	defer h.stateLock.Unlock()

	// Only allow transitioning from not-detaching to detaching.
	if !h.detach && detach {
		h.detach = detach
	}
	h.cancel()
}

// handleRunError is a convenience function to easily and correctly handle
// terminal errors during the task run lifecycle.
func (h *taskHandle) handleRunError(err error, context string) {
	h.stateLock.Lock()
	h.completedAt = time.Now()
	h.exitResult.ExitCode = 1
	h.exitResult.Err = fmt.Errorf("%s: %v", context, err)
	h.stateLock.Unlock()
}

// stopTask is used to stop the Triton instance, and monitor its status until it
// reaches the stopped state.
func (h *taskHandle) stopTask() error {
	h.logger.Info("Inside stopTask()")
	if err := h.tritonClient.StopTask(context.TODO(), h.instUUID); err != nil {
		return err
	}

	for {
		select {
		case <-time.After(5 * time.Second):
			status, err := h.tritonClient.DescribeTaskStatus(context.TODO(), h.instUUID)
			if err != nil {
				return err
			}

			// Check whether the status is in its final state, and log to provide
			// operator visibility.
			if status == tritonInstanceStatusStopped {
				h.logger.Info("triton instance has successfully been stopped")
				return nil
			}
			h.logger.Debug("continuing to monitor triton instance shutdown", "status", status)
		}
	}
}

// stopTask is used to stop the Triton instance, and monitor its status until it
// reaches the stopped state.
func (h *taskHandle) destroyTask() error {
	if err := h.tritonClient.DestroyTask(context.TODO(), h.instUUID); err != nil {
		return err
	}

	for {
		select {
		case <-time.After(5 * time.Second):
			status, err := h.tritonClient.DescribeTaskStatus(context.TODO(), h.instUUID)
			if err != nil {
				return err
			}

			// Check whether the status is in its final state, and log to provide
			// operator visibility.
			if status == tritonInstanceStatusDeleted {
				h.logger.Info("triton instance has successfully been destroyed")
				return nil
			}
			h.logger.Debug("continuing to monitor triton instance destruction", "status", status)
		}
	}

	return nil
}
