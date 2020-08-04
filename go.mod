module github.com/teutat3s/nomad-driver-triton

go 1.14

require (
	github.com/Smithx10/nomad-driver-triton v0.0.2
	github.com/fsouza/go-dockerclient v1.6.5
	github.com/go-ole/go-ole v1.2.2 // indirect
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/go-hclog v0.14.1
	github.com/hashicorp/nomad v0.12.1
	github.com/hpcloud/tail v1.0.1-0.20180514194441-a1dbeea552b7 // indirect
	github.com/joyent/triton-go v1.8.4
	github.com/vmihailenco/msgpack v4.0.2+incompatible // indirect
	gopkg.in/fsnotify/fsnotify.v1 v1.4.7 // indirect
)

replace github.com/godbus/dbus => github.com/godbus/dbus v5.0.1+incompatible
