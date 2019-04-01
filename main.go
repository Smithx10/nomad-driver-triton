package main

import (
	"github.com/Smithx10/nomad-driver-triton/plugin"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/plugins"
)

func main() {
	plugins.Serve(factory)
}

// factory returns a new instance of the IIS Driver plugin
func factory(log hclog.Logger) interface{} {
	return plugin.NewDriver(log)
}
