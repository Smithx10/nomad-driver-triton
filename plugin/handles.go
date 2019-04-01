package plugin

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/drivers/shared/executor"
	"github.com/hashicorp/nomad/plugins/drivers"
)

type taskHandle struct {
	tth        *TritonTaskHandler
	tritonTask *TritonTask
	logger     hclog.Logger
	exec       executor.Executor

	// stateLock syncs access to all fields below
	stateLock sync.RWMutex

	taskConfig  *drivers.TaskConfig
	procState   drivers.TaskState
	startedAt   time.Time
	completedAt time.Time
	exitResult  *drivers.ExitResult
	waitCh      chan struct{}
}

func (h *taskHandle) TaskStatus() *drivers.TaskStatus {
	h.stateLock.RLock()
	defer h.stateLock.RUnlock()

	return &drivers.TaskStatus{
		ID:          h.taskConfig.ID,
		Name:        h.taskConfig.Name,
		State:       h.tritonTask.status,
		StartedAt:   h.startedAt,
		CompletedAt: h.completedAt,
		ExitResult:  h.exitResult,
		DriverAttributes: map[string]string{
			"Brand":           h.tritonTask.instance.Brand,
			"ComputeNode":     h.tritonTask.instance.ComputeNode,
			"FirewallEnabled": strconv.FormatBool(h.tritonTask.instance.FirewallEnabled),
			"Image":           h.tritonTask.instance.Image,
			"Nname":           h.tritonTask.instance.Name,
			"Package":         h.tritonTask.instance.Package,
			"PrimaryIP":       h.tritonTask.instance.PrimaryIP,
			"Type":            h.tritonTask.instance.Type,
		},
	}
}

func (h *taskHandle) IsRunning() bool {
	h.stateLock.RLock()
	defer h.stateLock.RUnlock()
	return h.procState == drivers.TaskStateRunning
}

func (h *taskHandle) run() {
	h.stateLock.Lock()
	if h.exitResult == nil {
		h.exitResult = &drivers.ExitResult{}
	}
	h.stateLock.Unlock()

	defer close(h.waitCh)

	h.logger.Info("in the run loop")
	h.logger.Info(fmt.Sprintln(h.TaskStatus()))

	h.tth.GetInstStatus(h.tritonTask)

	h.logger.Info("returned from instStatus")

	h.stateLock.Lock()
	defer h.stateLock.Unlock()

	h.procState = drivers.TaskStateExited
	h.completedAt = time.Now()
}

type taskStore struct {
	store map[string]*taskHandle
	lock  sync.RWMutex
}

func newTaskStore() *taskStore {
	return &taskStore{store: map[string]*taskHandle{}}
}

func (ts *taskStore) Set(id string, handle *taskHandle) {
	ts.lock.Lock()
	defer ts.lock.Unlock()
	ts.store[id] = handle
}

func (ts *taskStore) Get(id string) (*taskHandle, bool) {
	ts.lock.RLock()
	defer ts.lock.RUnlock()
	t, ok := ts.store[id]
	return t, ok
}

func (ts *taskStore) Delete(id string) {
	ts.lock.Lock()
	defer ts.lock.Unlock()
	delete(ts.store, id)
}
