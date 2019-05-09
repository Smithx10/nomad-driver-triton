job "job" {
  datacenters = ["dc1"]
  type        = "service"

  update {
    canary       = 1
    max_parallel = 1
  }

  group "group" {
    count = 1

    task "task" {
      driver = "triton"

      service {
        name         = "job-group-task-ssh"
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
          name = "sample-512M"
        }

        api_type = "cloud_api"

        cloud_api {
          #image = "50719951-4dab-4fc0-9549-b36466614324"
          image {
            name = "centos-7"

            version = "20180323"

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
          "rawrsauce",
        ]

        tags = {
          fwtag = "true"
        }

        fwrules = {
          fwrule0 = "FROM any TO tag fwtag ALLOW tcp (PORT 22 AND PORT 8080)"
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
