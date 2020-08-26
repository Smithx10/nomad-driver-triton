package types

type DriverConfig struct {
}

type TaskConfig struct {
	APIType            string            `codec:"api_type" json:"api_type"`
	Cloud              CloudAPI          `codec:"cloud_api" json:"cloud_api"`
	Docker             DockerAPI         `codec:"docker_api" json:"docker_api"`
	Affinity           []string          `codec:"affinity" json:"affinity"`
	CNS                []string          `codec:"cns" json:"cns"`
	DeletionProtection bool              `codec:"deletion_protection" json:"deletion_protection"`
	FWEnabled          bool              `codec:"fwenabled" json:"fwenabled"`
	FWRules            map[string]string `codec:"fwrules" json:"fwrules"`
	Package            Package           `codec:"package" json:"package"`
	ExitStrategy       string            `codec:"exit_strategy" json:"exit_strategy"`
	Tags               map[string]string `codec:"tags" json:"tags"`
}

type CloudAPI struct {
	CloudConfig string     `codec:"cloud_config" json:"cloud_config"`
	Image       CloudImage `codec:"image" json:"image"`
	Networks    []Network  `codec:"networks" json:"networks"`
	UserData    string     `codec:"user_data" json:"user_data"`
	UserScript  string     `codec:"user_script" json:"user_script"`
}

type Network struct {
	Name string `codec:"name" json:"name"`
	UUID string `codec:"uuid" json:"uuid"`
}

type DockerAuth struct {
	Username   string `codec:"username"`
	Password   string `codec:"password"`
	Email      string `codec:"email"`
	ServerAddr string `codec:"server_address"`
}

type DockerImage struct {
	Name     string `codec:"name" json:"name"`
	Tag      string `codec:"tag" json:"tag"`
	AutoPull bool   `codec:"auto_pull" json:"auto_pull"`
}

type Package struct {
	Name    string `codec:"name" json:"name"`
	UUID    string `codec:"uuid" json:"uuid"`
	Version string `codec:"version" json:"version"`
}

type CloudImage struct {
	Name       string `codec:"name" json:"name"`
	UUID       string `codec:"uuid" json:"uuid"`
	MostRecent bool   `codec:"most_recent" json:"most_recent"`
	Version    string `codec:"version" json:"version"`
}

type Ports struct {
	TCP        []int `codec:"tcp" json:"tcp"`
	UDP        []int `codec:"udp" json:"udp"`
	PublishAll bool  `codec:"publish_all" json:"publish_all"`
}

type LogConfig struct {
	Type   string            `codec:"type" json:"type"`
	Config map[string]string `codec:"config" json:"config"`
}

type DockerAPI struct {
	Cmd            []string          `codec:"cmd" json:"cmd"`
	Entrypoint     []string          `codec:"entrypoint" json:"entrypoint"`
	OpenStdin      bool              `codec:"openstdin" json:"openstdin"`
	StdInOnce      bool              `codec:"stdinonce" json:"stdinonce"`
	TTY            bool              `codec:"tty" json:"tty"`
	WorkingDir     string            `codec:"workingdir" json:"workingdir"`
	Image          DockerImage       `codec:"image" json:"image"`
	Auth           DockerAuth        `codec:"auth"`
	Labels         map[string]string `codec:"labels" json:"labels"`
	PublicNetwork  string            `codec:"public_network" json:"public_network"`
	PrivateNetwork string            `codec:"private_network" json:"private_network"`
	RestartPolicy  string            `codec:"restart_policy" json:"restart_policy"`
	Ports          Ports             `codec:"ports" json:"ports"`
	Hostname       string            `codec:"hostname" json:"hostname"`
	DNS            []string          `codec:"dns" json:"dns"`
	DNSSearch      []string          `codec:"dns_search" json:"dns_search"`
	User           string            `codec:"user" json:"user"`
	Domainname     string            `codec:"domain_name" json:"domain_name"`
	ExtraHosts     []string          `codec:"extra_hosts" json:"extra_hosts"`
	LogConfig      LogConfig         `codec:"log_config" json:"log_config"`
}
