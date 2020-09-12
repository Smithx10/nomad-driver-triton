module github.com/Smithx10/nomad-driver-triton

go 1.14

require (
	github.com/Microsoft/hcsshim v0.8.9 // indirect
	github.com/container-storage-interface/spec v1.2.0 // indirect
	github.com/containerd/containerd v1.3.7 // indirect
	github.com/containernetworking/plugins v0.7.6 // indirect
	github.com/creack/pty v1.1.11 // indirect
	github.com/fsouza/go-dockerclient v1.6.5
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/gofrs/uuid v3.3.0+incompatible
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.1 // indirect
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/go-hclog v0.14.1
	github.com/hashicorp/go-version v1.2.1 // indirect
	github.com/hashicorp/nomad v0.10.3-0.20200311101349-a21262a3d28e
	github.com/hashicorp/serf v0.9.4 // indirect
	github.com/hpcloud/tail v1.0.1-0.20180514194441-a1dbeea552b7 // indirect
	github.com/joyent/triton-go v1.8.5
	github.com/kr/pty v1.1.8 // indirect
	github.com/mattn/go-colorable v0.1.7 // indirect
	github.com/mitchellh/go-testing-interface v1.0.4 // indirect
	github.com/mitchellh/mapstructure v1.3.3 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/shirou/gopsutil v2.20.7+incompatible // indirect
	github.com/stretchr/testify v1.5.1
	github.com/vmihailenco/msgpack v4.0.4+incompatible // indirect
	github.com/zclconf/go-cty v1.4.2 // indirect
	golang.org/x/text v0.3.3 // indirect
	google.golang.org/appengine v1.6.6 // indirect
	gopkg.in/fsnotify/fsnotify.v1 v1.4.7 // indirect
)

replace github.com/godbus/dbus => github.com/godbus/dbus v5.0.1+incompatible

// try rebased nomad with remote-task
replace github.com/hashicorp/nomad => github.com/smithx10/nomad v0.9.1-0.20200910182001-47562d9edcf6
