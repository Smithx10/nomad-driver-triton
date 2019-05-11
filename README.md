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

You can access the Web UI of Nomad on :4646/ui, and Consul on :8500/ui 


### Nomad Config Inputs
```
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
                "tags":      hclspec.NewBlockAttrs("tags", "string", false),
                "affinity":  hclspec.NewAttr("affinity", "list(string)", false),
                "deletion_protection": hclspec.NewAttr("deletion_protection", "bool", false),
                "fwenabled": hclspec.NewAttr("fwenabled", "bool", false),
                "fwrules":   hclspec.NewBlockAttrs("fwrules", "string", false),
                "cns":       hclspec.NewAttr("cns", "list(string)", false),
                "package": hclspec.NewBlock("package", true, hclspec.NewObject(map[string]*hclspec.Spec{
                        "name":    hclspec.NewAttr("name", "string", false),
                        "uuid":    hclspec.NewAttr("uuid", "string", false),
                        "version": hclspec.NewAttr("version", "string", false),
                })),
        })
```

# Contribute 
Read https://github.com/hashicorp/nomad/blob/website/plugin-docs/website/source/docs/internals/plugins/task-drivers.html.md and then make changes and open a PR.<Paste>