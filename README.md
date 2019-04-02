# nomad-driver-triton
HashiCorp Nomad Triton driver plugin 


# Getting Started
### Running Nomad with Consul:

Build Nomad and place the binary in the plugins directory.  This is specified in the config.hcl
```
go build -v . && sudo mv nomad-driver-triton plugins
```

Download Consul from https://www.consul.io/downloads.html,  run it in dev mode to get started quickly.
```
consul agent -dev -bind 0.0.0.0 -client 0.0.0.0
```

Evaluate the account that you want the Nomad Agent to run against.  
```
eval "$(triton env bruce_dev)" && eval "$(ssh-agent)" && ssh-add
```

Run Nomad in Dev Mode also, provide the absolute path "./" Doesn't work. :( 
```
nomad agent -dev -config=config.hcl -data-dir=/home/arch/go/src/github.com/Smithx10/nomad-driver-triton -plugin-dir=/h
ome/arch/go/src/github.com/Smithx10/nomad-driver-triton/plugins -bind=0.0.0.0
```

Run an example.  Please populate the example.nomad with the correct values that fit your environment.
```
nomad run example.nomad
```
