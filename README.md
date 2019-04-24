# nomad-driver-triton
HashiCorp Nomad Triton driver plugin 


# Getting Started
### Running Nomad with Consul:

Install the Nomad 0.9.0-rc1 that supports plugins.  https://releases.hashicorp.com/nomad/0.9.0-rc1/


Build the Nomad Plugin and place the binary in the plugins directory.  This is specified in the config.hcl
```
go get -v github.com/Smithx10/nomad-driver-triton
cd ~/go/src/github.com/Smithx10/nomad-driver-triton/ 
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

You can access the Web UI of Nomad on :4646/ui, and Consul on :8500/ui 


### Nomad Config Inputs
```
        taskConfigSpec = hclspec.NewObject(map[string]*hclspec.Spec{
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
                "package": hclspec.NewBlock("package", true, hclspec.NewObject(map[string]*hclspec.Spec{
                        "name":    hclspec.NewAttr("name", "string", false),
                        "uuid":    hclspec.NewAttr("uuid", "string", false),
                        "version": hclspec.NewAttr("version", "string", false),
                })),
                "user_data":    hclspec.NewAttr("user_data", "string", false),
                "cloud_config": hclspec.NewAttr("cloud_config", "string", false),
                "user_script":  hclspec.NewAttr("user_script", "string", false),
                "tags":         hclspec.NewBlockAttrs("tags", "string", false),
                "affinity":     hclspec.NewAttr("affinity", "string", false),
                "fwenabled":    hclspec.NewAttr("fwenabled", "bool", false),
                "fwrules":      hclspec.NewBlockAttrs("fwrules", "string", false),
                "cns":          hclspec.NewAttr("cns", "list(string)", false),
 ```


# Contribute 
Read https://github.com/hashicorp/nomad/blob/website/plugin-docs/website/source/docs/internals/plugins/task-drivers.html.md and then make changes and open a PR.



