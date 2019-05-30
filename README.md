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

#### api_type _string_
Dictates which Triton Provisioning API you want to use. 
```
"api_type": "cloud_api" || "docker_api"
```

#### docker_api _stanza_
Contains the parameters required to provision a docker instance on Triton.
```
"docker_api": {}
```
#### docker_api.cmd _[]string_
Command to run specified as a string or an array of strings.
```
"docker_api": {
  "cmd": [
    "date",
  ]
}
```
#### docker_api.entrypoint _[]string_
Set the entry point for the container as a string or an array of strings.
```
"docker_api": {
  "entrypoint": [
    "date",
  ]
}
```
#### docker_api.openstdin _bool_
Boolean value, opens stdin.
```
"docker_api": {
  "openstdin": false
}
```
#### docker_api.stdinonce _bool_
Boolean value, close stdin after the 1 attached client disconnects.
```
"docker_api": {
  "stdinonce": false
}
```
#### docker_api.tty _bool_
Boolean value, Attach standard streams to a tty, including stdin if it is not closed.
```
"docker_api": {
  "tty": false
}
```
#### docker_api.workingdir _string_
A string specifying the working directory for commands to run in.
```
"docker_api": {
  "workingdir": "/foo/bar"
}
```
#### docker_api.hostname _string_
A string value containing the hostname to use for the container. This must be a valid RFC 1123 hostname.
```
"docker_api": {
  "hostname": "foo" 
}
```
#### docker_api.dns _[]string_
A list of DNS servers for the container to use.
```
"docker_api": {
  "dns": [
    "8.8.8.8",
    "8.8.4.4",
  ]
}
```
#### docker_api.dns_search _[]string_
A list of DNS search domains
```
"docker_api": {
  "dns_search": [
    "foo.com",
    "rxcorp.com",
  ] 
}
```
#### docker_api.extra_hosts _[]string_
A list of hostnames/IP mappings to add to the container’s /etc/hosts file. Specified in the form ["hostname:IP"].
```
"docker_api": {
  "extra_hosts": [
    "foo:10.45.136.2",
    "bar:10.45.137.3",
  ]
}
```
#### docker_api.user _string_
A string value specifying the user inside the container.
```
"docker_api": {
  "user": "foo" 
}
```
#### docker_api.domain_name _string_
A string value containing the domain name to use for the container.
```
"docker_api": {
  "domain_name": "foo.com" 
}
```
#### docker_api.labels _map[string]string_
Labels - Adds a map of labels to a container. To specify a map: {"key":"value", ... }
```
"docker_api": {
  "labels" {
    group         = "webservice-cache"
    bob.bill.john = "label"
    test          = "test"
  }
}
```
#### docker_api.public_network _string_
A string value specifying the public network to use inside the container.
```
"docker_api": {
  "public_network": "sdc_nat" 
}
```
#### docker_api.private_network _string_
A string value specifying the private network to use inside the container.
```
"docker_api": {
  "private_network": "sdc_nat" 
}
```
#### docker_api.log_config _stanza_
Log configuration for the container.
```
"docker_api": {
  "log_config": {}
}
```
#### docker_api.log_config.type _string_
A string value specifying the docker log driver type. see https://github.com/joyent/sdc-docker/blob/master/docs/api/features/logdrivers.md, https://www.joyent.com/blog/docker-log-drivers 
```
"docker_api": {
  "log_config" {
    "type": "syslog",
  }
}
```
#### docker_api.log_config.config _map[string]string_
A map of string values specifying the log options for the log driver specified.
```
"docker_api": {
  "log_config" {
    "type": "syslog",
    "config" {
      "syslog-address" = "tcp://host:port"
    }
  }
}
```
#### docker_api.ports _stanza_
A stanza defining which tcp and udp ports you would like to publish.
```
"docker_api": {
  "ports": {}
}
```
#### docker_api.ports.tcp _[]int_
A list of int defining which tcp ports you would like to publish.
```
"docker_api": {
  "ports": {
    tcp = [
      6379,
    ]
  }
}
```
#### docker_api.ports.udp _[]int_
A list defining which udp ports you would like to publish.
```
"docker_api": {
  "ports": {
    udp = [
      6379,
    ]
  }
}
```
#### docker_api.ports.publish_all _bool_
Allocates an ephemeral host port for all of a container’s exposed ports. Specified as a boolean value.
```
"docker_api": {
  "publish_all": true
}
```
#### docker_api.image _stanza_
Specifies the image name,tag and pull policy to use for the container
```
"docker_api": {
  image {
    name      = "redis"
    tag       = "latest"
    auto_pull = true
  }
}
```
#### docker_api.name _string_
Specifies the image name to use for the container.
```
"docker_api": {
  image {
    name      = "redis"
    tag       = "latest"
    auto_pull = true
  }
}
```
#### docker_api.tag _string_
Specifies the image tag to use for the container.  Defaults to latest
```
"docker_api": {
  image {
    name      = "redis"
    tag       = "latest"
    auto_pull = true
  }
}
```
#### docker_api.auto_pull _bool_
A bool specifying if the Triton Docker API will attempt to pull the image.
```
"docker_api": {
  image {
    name      = "redis"
    tag       = "latest"
    auto_pull = true
  }
}
```
#### docker_api.restart_policy _string_
The behavior to apply when the container exits. The value is an object with a Name property of either "always" to always restart, "unless-stopped" to restart always except when user has manually stopped the container or "on-failure" to restart only when the container exit code is non-zero. If on-failure is used, MaximumRetryCount controls the number of times to retry before giving up. The default is not to restart. (optional) An ever increasing delay (double the previous delay, starting at 100mS) is added before each restart to prevent flooding the server.
```
"docker_api": {
  "restart_policy": "always"
}
```

# Contribute 
Read https://github.com/hashicorp/nomad/blob/website/plugin-docs/website/source/docs/internals/plugins/task-drivers.html.md and then make changes and open a PR.<Paste>
