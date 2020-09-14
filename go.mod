module github.com/Smithx10/nomad-driver-triton

go 1.14

require (
	github.com/LK4D4/joincontext v0.0.0-20171026170139-1724345da6d5 // indirect
	github.com/Microsoft/hcsshim v0.8.9 // indirect
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/cockroachdb/apd v1.1.0 // indirect
	github.com/container-storage-interface/spec v1.2.0 // indirect
	github.com/containerd/containerd v1.3.7 // indirect
	github.com/containernetworking/plugins v0.7.6 // indirect
	github.com/coreos/bbolt v1.3.2 // indirect
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/creack/pty v1.1.11 // indirect
	github.com/fsouza/go-dockerclient v1.6.5
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/gofrs/uuid v3.3.0+incompatible
	github.com/golang/groupcache v0.0.0-20190129154638-5b532d6fd5ef // indirect
	github.com/gorhill/cronexpr v0.0.0-20180427100037-88b0669f7d75 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.1 // indirect
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.9.0 // indirect
	github.com/hashicorp/consul/api v1.7.0 // indirect
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/go-hclog v0.14.1
	github.com/hashicorp/go-msgpack v1.1.5 // indirect
	github.com/hashicorp/go-plugin v1.3.0 // indirect
	github.com/hashicorp/go-version v1.2.1 // indirect
	github.com/hashicorp/nomad v0.12.4
	//github.com/hashicorp/nomad v0.10.3-0.20200309114918-e0fcd4da9d18
	github.com/hashicorp/serf v0.9.4 // indirect
	github.com/hpcloud/tail v1.0.1-0.20180514194441-a1dbeea552b7 // indirect
	github.com/jackc/fake v0.0.0-20150926172116-812a484cc733 // indirect
	github.com/jackc/pgx v3.3.0+incompatible // indirect
	github.com/jonboulle/clockwork v0.1.0 // indirect
	github.com/joyent/triton-go v1.6.1
	github.com/kr/pty v1.1.8 // indirect
	github.com/lib/pq v1.1.1 // indirect
	github.com/mattn/go-colorable v0.1.7 // indirect
	github.com/mitchellh/copystructure v1.0.0 // indirect
	github.com/mitchellh/go-testing-interface v1.0.4 // indirect
	github.com/mitchellh/hashstructure v1.0.0 // indirect
	github.com/mitchellh/mapstructure v1.3.3 // indirect
	github.com/olekukonko/tablewriter v0.0.0-20180130162743-b8a9be070da4 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/prometheus/tsdb v0.7.1 // indirect
	github.com/rs/zerolog v1.4.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/sean-/conswriter v0.0.0-20180208195008-f5ae3917a627 // indirect
	github.com/sean-/pager v0.0.0-20180208200047-666be9bf53b5 // indirect
	github.com/shirou/gopsutil v2.20.7+incompatible // indirect
	github.com/shopspring/decimal v0.0.0-20180709203117-cd690d0c9e24 // indirect
	github.com/soheilhy/cmux v0.1.4 // indirect
	github.com/spf13/afero v1.2.1 // indirect
	github.com/spf13/cobra v0.0.5 // indirect
	github.com/stretchr/testify v1.5.1
	github.com/tmc/grpc-websocket-proxy v0.0.0-20190109142713-0ad062ec5ee5 // indirect
	github.com/vmihailenco/msgpack v4.0.4+incompatible // indirect
	github.com/xiang90/probing v0.0.0-20190116061207-43a291ad63a2 // indirect
	github.com/zclconf/go-cty v1.4.2 // indirect
	golang.org/x/text v0.3.3 // indirect
	google.golang.org/appengine v1.6.6 // indirect
	gopkg.in/fsnotify/fsnotify.v1 v1.4.7 // indirect
)

replace github.com/godbus/dbus => github.com/godbus/dbus v5.0.1+incompatible

// use lower-case sirupsen
replace github.com/Sirupsen/logrus v1.0.6 => github.com/sirupsen/logrus v1.0.6

replace github.com/Sirupsen/logrus v1.2.0 => github.com/sirupsen/logrus v1.2.0

replace github.com/Sirupsen/logrus v1.4.1 => github.com/sirupsen/logrus v1.4.1

replace github.com/Sirupsen/logrus v1.4.2 => github.com/sirupsen/logrus v1.4.2

// don't use shirou/gopsutil, use the hashicorp fork
replace github.com/shirou/gopsutil => github.com/hashicorp/gopsutil v2.17.13-0.20190117153606-62d5761ddb7d+incompatible

// don't use ugorji/go, use the hashicorp fork
// replace github.com/ugorji/go => github.com/hashicorp/go-msgpack v0.0.0-20190927123313-23165f7bc3c2
replace github.com/ugorji/go => github.com/ugorji/go/codec v1.1.7

replace github.com/ugorji/go v1.1.7 => github.com/ugorji/go/codec v0.0.0-20190204201341-e444a5086c43

// fix the version of hashicorp/go-msgpack to 96ddbed8d05b
replace github.com/hashicorp/go-msgpack => github.com/hashicorp/go-msgpack v0.0.0-20191101193846-96ddbed8d05b

// try rebased nomad with remote-task
replace github.com/hashicorp/nomad => /home/arch/go/src/github.com/hashicorp/nomad
