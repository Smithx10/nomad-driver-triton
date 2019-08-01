job "docker" {
  datacenters = ["dc1"]
  type        = "service"

  group "docker" {
    count = 3

    task "webservice" {
      driver = "docker"

      resources {
        network {
          port "db" {}
        }
      }

      service {
        name         = "${TASKGROUP}-redis"
        tags         = ["global", "cache"]
        port         = "db"
        address_mode = "driver"

        check {
          name     = "alive"
          type     = "tcp"
          interval = "10s"
          timeout  = "2s"

          check_restart {
            limit           = 3
            grace           = "90s"
            ignore_warnings = false
          }
        }
      }

      config {
        image = "redis:3.2"

        port_map = {
          db = 6379
        }

        labels {
          group = "webservice-cache"
        }
      }
    }
  }
}
