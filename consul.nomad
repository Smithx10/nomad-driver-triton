job "consul" {
  datacenters = ["dc1"]
  type        = "service"

  update {
    canary       = 2
    max_parallel = 2
  }

  group "consul" {
    count = 3

    task "consul" {
      driver = "triton"

      resources {
        cpu    = 20
        memory = 10
      }

      template {
        destination = "local/file.yml"

        env = true

        data = <<EOH
          SUMESH="{{ env "NOMAD_TASK_DIR" }}"
          FRUSTRATED="{{ env "node.unique.id" }}"
        EOH
      }

      service {
        name         = "consul-ssh"
        tags         = ["ssh", "moore"]
        port         = "22"
        address_mode = "driver"

        check {
          type         = "tcp"
          port         = "22"
          interval     = "10s"
          timeout      = "2s"
          address_mode = "driver"

          check_restart {
            limit           = 3
            grace           = "90s"
            ignore_warnings = false
          }
        }
      }

      service {
        name         = "consul-ui"
        tags         = ["consul", "brent"]
        port         = "8500"
        address_mode = "driver"

        check {
          type         = "http"
          port         = "8500"
          path         = "/ui"
          interval     = "5s"
          timeout      = "2s"
          address_mode = "driver"

          check_restart {
            limit           = 3
            grace           = "90s"
            ignore_warnings = false
          }
        }
      }

      config {
        package {
          name = "sample-512M"
        }

        #deletion_protection = true

        api_type = "cloud_api"
        cloud_api {
          image {
            name = "img-consul-master"

            #uuid = "50719951-4dab-4fc0-9549-b36466614324"


            version = "1554100930"

            #version = "1554126304"

            #most_recent = true
          }

          networks = [
            {
              name = "sdc_nat"
            },
            {
              name = "consul"
            },
          ]
        }
        #fwenabled = true
        cns = [
          "consul",
        ]
        tags = {
          consul = "true"
        }
        fwrules = {
          anytoconsului = "FROM any TO tag consul ALLOW tcp (PORT 22 AND PORT 8500)"
          consultcp     = "FROM tag consul TO tag consul ALLOW tcp PORT all"
          consuludp     = "FROM tag consul TO tag consul ALLOW udp PORT all"
        }
        exit_strategy = "stopped"
      }

      env {
        CONTAINERPILOT          = "/etc/containerpilot.json5"
        CONSUL_AGENT            = "1"
        CONSUL_BOOTSTRAP_EXPECT = "3"
        CONSUL                  = "consul.svc.bruce-dev.us-east-1.cns.bdf-cloud.iqvia.net"
      }

      meta {
        my-key = "my-value"
      }
    }
  }
}
