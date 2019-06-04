job "bhyve" {
  datacenters = ["dc1"]
  type        = "service"

  update {
    canary       = 1
    max_parallel = 1
  }

  group "example" {
    count = 2

    task "task" {
      driver = "triton"

      service {
        name         = "bhyve-demo-ssh"
        tags         = ["example"]
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

      config {
        package {
          name = "sample-2G"
        }

        api_type = "cloud_api"

        cloud_api {
          #image = "50719951-4dab-4fc0-9549-b36466614324"
          image {
            name = "ubuntu-certified-18.04"

            version = "20180808"

            #most_recent = true
          }

          networks = [
            {
              name = "sdc_nat"
            },
          ]
        }

        fwenabled = true

        cns = [
          "bhyve_example",
        ]

        tags = {
          fwtag = "true"
        }

        fwrules = {
          fwrule0 = "FROM any TO tag fwtag ALLOW tcp PORT 22"
        }
      }

      env {
        my_key = "test"
      }

      meta {
        my-key = "my-value"
      }
    }
  }
}
