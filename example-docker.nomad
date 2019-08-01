job "redis" {
  datacenters = ["dc1"]
  type        = "service"

  update {
    canary            = 1
    max_parallel      = 1
    healthy_deadline  = "8m"
    progress_deadline = "10m"
  }

  group "redis" {
    count = 5

    task "redis" {
      driver = "triton"

      resources {
        cpu    = 20
        memory = 10
      }

      service {
        name         = "${TASKGROUP}-redis"
        tags         = ["global", "cache"]
        port         = 6379
        address_mode = "driver"

        check {
          name         = "alive"
          type         = "tcp"
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
        api_type = "docker_api"

        docker_api {
          public_network = "sdc_nat"

          private_network = "My-Fabric-Network"

          labels {
            group         = "webservice-cache"
            bob.bill.john = "label"
            test          = "test"
          }

          ports {
            tcp = [
              6379,
            ]
          }

          image {
            name      = "redis"
            tag       = "latest"
            auto_pull = true
          }
        }

        package {
          name = "sample-512M"
        }

        fwenabled = false

        cns = [
          "redis",
        ]

        tags = {
          redis = "true"
        }

        fwrules {
          anytoredis = "FROM any TO tag redis ALLOW tcp PORT 6379"
          redistcp   = "FROM tag redis TO tag redis ALLOW tcp PORT all"
          redisudp   = "FROM tag redis TO tag redis ALLOW udp PORT all"
        }
      }

      env {
        envtest = "test"
      }

      meta {
        my-key = "my-value"
      }
    }
  }
}
